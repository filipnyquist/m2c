/**
 * m2c bridge for Pi.
 *
 * m2c (https://github.com/filipnyquist/m2c) is a recording proxy: it writes every HTTP
 * flow that goes through it into an embedded ClickHouse, attributed to the agent session
 * and the tool that sent it. This extension wires it into a pi session:
 *
 *   1. On session start it starts (or attaches to) an m2c recording proxy for the session.
 *   2. Bash commands run through that proxy, tagged with the session id and the tool-call
 *      id, so the traffic can be grouped per call in m2c's timeline.
 *   3. It registers m2c's MCP server, scoped to this session, so the model can search,
 *      read, diff and replay the traffic it just produced.
 *
 * The point of the loop: the model makes a request, and can then read the exact request
 * and response it made (bodies included) instead of guessing from the tool output, or
 * making the request again.
 *
 * The proxy's output goes to <data>/proxy.log, and `/m2c` shows the tail of it. The
 * repeater is on, so the model can resend a recorded request through the proxy (it sends
 * real requests to the target).
 *
 * Configuration (environment):
 *   M2C_BRIDGE=off      the extension does nothing at all
 *   M2C_BRIDGE=manual   never start a proxy; attach to a running one if there is one
 *   M2C_DATA            the scan directory (default: <agent-dir>/m2c/<session id>)
 *   M2C_BIN             the m2c executable (default: m2c on PATH)
 *   M2C_LISTEN          the proxy's listen address (default: a free port on 127.0.0.1)
 *   M2C_API_LISTEN      the API's listen address (default: a free port on 127.0.0.1)
 *   M2C_REPEATER        off, admin or on (default: on): who may resend recorded requests
 *
 * Requires the m2c CLI on PATH: `uv tool install git+https://github.com/filipnyquist/m2c`.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createBashTool } from "@earendil-works/pi-coding-agent";
import { AsyncLocalStorage } from "node:async_hooks";
import { spawn, type ChildProcess } from "node:child_process";
import { closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, rmdirSync } from "node:fs";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";

/** The oldest m2c this extension works with. */
const MIN_M2C_VERSION = "0.1.0";

/** m2c's session name: letters, digits, `_` and `-`. */
const SESSION_RE = /[^A-Za-z0-9_-]/g;
/** m2c's call id: letters, digits, `_`, `.`, `~` and `-`. */
const CALL_RE = /[^A-Za-z0-9._~-]/g;

/** Tools the model gets without asking for them; the rest are one search away. */
const DIRECT_TOOLS = ["traffic_search", "traffic_get", "traffic_wait", "traffic_events", "traffic_report"];
/** Every tool m2c's MCP server offers. */
const ALL_TOOLS = [
	...DIRECT_TOOLS,
	"traffic_stats",
	"traffic_sessions",
	"traffic_grep",
	"traffic_diff",
	"traffic_suggest",
	"traffic_annotate",
	"traffic_timeline",
	"traffic_sse",
	"traffic_ws",
	"traffic_grpc",
	"traffic_curl",
];

type Scan = {
	dataDir: string;
	session: string;
	apiUrl: string;
	proxyAddr: string;
	adminToken: string;
	/** Where the proxy's own output goes: its warnings and its start-up banner. */
	proxyLog: string;
	/** The proxy environment for this session (no call id yet). */
	env: Record<string, string>;
	/** The proxy this extension started, if any. */
	child: ChildProcess | null;
	/** True when the proxy was already running and we only attached to it. */
	attached: boolean;
};

export default function (pi: ExtensionAPI) {
	const mode = (process.env.M2C_BRIDGE ?? "auto").toLowerCase();
	if (["off", "0", "false", "none"].includes(mode)) return;

	const m2cBin = process.env.M2C_BIN || "m2c";
	const agentDir = process.env.PI_CODING_AGENT_DIR || join(homedir(), ".pi", "agent");

	let scan: Scan | null = null;
	let starting: Promise<Scan | null> | null = null;
	let warned = false;

	/** The tool call id of the bash call that is running right now. */
	const currentCall = new AsyncLocalStorage<{ callId: string }>();

	// ---------------------------------------------------------------- bash tool

	// The bash tool is replaced with one that knows about the proxy. Everything else
	// about it is the built-in behaviour: same schema, same rendering, same limits.
	const bashTool = createBashTool(process.cwd(), {
		spawnHook: ({ command, cwd, env }) => {
			if (!scan) return { command, cwd, env };
			const callId = currentCall.getStore()?.callId;
			return { command, cwd, env: { ...env, ...proxyEnv(scan, callId) } };
		},
	});

	pi.registerTool({
		...bashTool,
		execute: (id, params, signal, onUpdate, ctx) =>
			currentCall.run({ callId: sanitizeCall(id) }, () => bashTool.execute(id, params, signal, onUpdate, ctx)),
	});

	// ---------------------------------------------------------------- lifecycle

	pi.on("session_start", async (_event, ctx) => {
		const result = await ensureProxy(ctx);
		if (!result) return;

		scan = result;
		registerMcp(pi, scan);

		if (ctx.hasUI) {
			ctx.ui.notify(
				`m2c: recording this session's traffic on ${scan.proxyAddr} (${scan.dataDir})`,
				"info",
			);
		}

		const version = await m2cVersion(m2cBin);
		if (version && compareVersions(version, MIN_M2C_VERSION) < 0) {
			const message = `m2c: this extension needs m2c ${MIN_M2C_VERSION} or later (found ${version})`;
			if (ctx.hasUI) ctx.ui.notify(message, "warn");
			else console.error(message);
		}
	});

	pi.on("session_shutdown", async () => {
		await stopProxy(scan);
		scan = null;
	});

	// ---------------------------------------------------------------- commands

	pi.registerCommand("m2c", {
		description: "Show the m2c recording status for this session",
		handler: async (_args, ctx) => {
			if (!scan) {
				ctx.ui.notify("m2c: no recording proxy for this session", "warn");
				return;
			}
			const stats = await run(m2cBin, ["stats", "--data", scan.dataDir]).catch(() => null);
			const lines = [
				`m2c session: ${scan.session}`,
				`proxy:      ${scan.proxyAddr}`,
				`api:        ${scan.apiUrl}`,
				`scan:       ${scan.dataDir}`,
				`ui:         ${scan.apiUrl}/ui/#token=${scan.adminToken}`,
				`attached:   ${scan.attached ? "yes (proxy was already running)" : "no (started by pi)"}`,
			];
			if (stats) lines.push("", stats.stdout.trimEnd());
			const log = logTail(scan.proxyLog);
			if (log) lines.push("", `proxy log (${scan.proxyLog}):`, log);
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});

	// ---------------------------------------------------------------- helpers

	async function ensureProxy(ctx: ExtensionContext): Promise<Scan | null> {
		if (starting) return starting;
		starting = (async () => {
			try {
				return await start(ctx);
			} catch (error) {
				if (!warned) {
					warned = true;
					const message = error instanceof Error ? error.message : String(error);
					if (ctx.hasUI) ctx.ui.notify(`m2c: ${message}`, "warn");
					else console.error(`m2c: ${message}`);
				}
				return null;
			} finally {
				starting = null;
			}
		})();
		return starting;
	}

	async function start(ctx: ExtensionContext): Promise<Scan | null> {
		const session = sanitizeSession(ctx.sessionManager.getSessionId());
		const dataDir = process.env.M2C_DATA
			? process.env.M2C_DATA
			: join(agentDir, "m2c", session);

		// A proxy that is already running for this directory: attach to it.
		const attached = await readApi(dataDir);
		if (attached) {
			return await finish(attached, session, dataDir, null, true);
		}

		if (mode === "manual") {
			throw new Error("no running proxy found for this data directory (M2C_BRIDGE=manual)");
		}

		mkdirSync(dataDir, { recursive: true });
		const listen = process.env.M2C_LISTEN || `127.0.0.1:${await freePort()}`;
		const api = process.env.M2C_API_LISTEN || `127.0.0.1:${await freePort()}`;

		// The proxy's own output goes to a file in the scan directory: its warnings are worth reading, and a
		// pi session that ends quietly should still leave a trace of why the proxy complained.
		const child = spawnProxy(
			m2cBin,
			["proxy", "--data", dataDir, "--listen", listen, "--api", api, "--repeater", process.env.M2C_REPEATER || "on"],
			join(dataDir, "proxy.log"),
		);

		// The proxy takes a while to come up (chDB opens the scan directory). If it dies or
		// never appears, give up instead of waiting for the whole timeout.
		const failed = new Promise<never>((_, reject) => {
			child.on("error", (error) =>
				reject(
					new Error(
						`cannot run ${m2cBin} (${(error as Error).message}); install it with "uv tool install git+https://github.com/filipnyquist/m2c"`,
					),
				),
			);
			child.on("exit", (code) =>
				reject(new Error(`${m2cBin} proxy exited with code ${code} before it came up`)),
			);
		});

		const info = await Promise.race([waitForApi(dataDir, 60_000), failed]).catch((error: Error) => {
			child.kill("SIGTERM");
			// Leave no empty scan directory behind when the proxy never ran.
			try {
				if (readdirSync(dataDir).length === 0) rmdirSync(dataDir);
			} catch {
				/* the directory is not empty, or it is gone already */
			}
			throw error;
		});
		if (!info) {
			child.kill("SIGTERM");
			throw new Error(`the recording proxy did not come up (${m2cBin} proxy --data ${dataDir})`);
		}
		return await finish(info, session, dataDir, child, false);
	}

	async function finish(
		info: { url: string; token: string; proxy: string },
		session: string,
		dataDir: string,
		child: ChildProcess | null,
		attached: boolean,
	): Promise<Scan> {
		const env = await proxyEnvironment(session, dataDir);
		return {
			dataDir,
			session,
			apiUrl: info.url,
			proxyAddr: info.proxy,
			adminToken: info.token,
			proxyLog: join(dataDir, "proxy.log"),
			env,
			child,
			attached,
		};
	}

	/** `m2c env` knows the proxy URL, the token and the CA bundle: let it build them. */
	async function proxyEnvironment(session: string, dataDir: string): Promise<Record<string, string>> {
		const result = await run(m2cBin, ["env", "--session", session, "--tool", "bash", "--data", dataDir, "--json"]);
		try {
			const parsed = JSON.parse(result.stdout);
			if (parsed && typeof parsed === "object") return parsed as Record<string, string>;
		} catch {
			/* fall through to the error below */
		}
		throw new Error("m2c env did not return a usable environment");
	}

	function registerMcp(api: ExtensionAPI, current: Scan) {
		try {
			api.registerMcpServer("m2c", {
				command: m2cBin,
				args: ["mcp", "--data", current.dataDir, "--session", current.session],
				description:
					"The HTTP traffic this session produced, recorded by m2c. Search it, read a flow in full, diff two requests, replay one.",
				exposure: "direct",
				toolExposure: Object.fromEntries(
					ALL_TOOLS.filter((name) => !DIRECT_TOOLS.includes(name)).map((name) => [name, "deferred"]),
				),
			});
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			console.error(`m2c: could not register the MCP server: ${message}`);
		}
	}
}

// ------------------------------------------------------------------ proxy env

/**
 * The proxy environment for one bash call. The proxy URL carries the identity of the
 * sender in its user name: `<session>.<tool>[.<call>]`, so each call's flows land in
 * the timeline under that call.
 */
function proxyEnv(scan: Scan, callId: string | undefined): Record<string, string> {
	const env = { ...scan.env };
	if (!callId) return env;

	const user = `${scan.session}.bash`;
	for (const [key, value] of Object.entries(env)) {
		if (!key.toUpperCase().endsWith("PROXY")) continue;
		if (typeof value !== "string" || !value.includes(`//${user}:`)) continue;
		env[key] = value.replace(`//${user}:`, `//${user}.${callId}:`);
	}
	return env;
}

// ------------------------------------------------------------------ utilities

/**
 * Start the proxy with its output in a file. A file descriptor, not a stream: pi runs extensions on Bun,
 * which cannot hand a stream without an underlying descriptor to a child process.
 */
function spawnProxy(bin: string, args: string[], log: string): ChildProcess {
	const fd = openSync(log, "a");
	try {
		return spawn(bin, args, { stdio: ["ignore", fd, fd], detached: false });
	} finally {
		closeSync(fd); // the child has its own copy
	}
}

/** The version of the m2c on PATH, or null when it can't be read. */async function m2cVersion(bin: string): Promise<string | null> {
	const result = await run(bin, ["--version"]).catch(() => null);
	if (!result || result.code !== 0) return null;
	const match = result.stdout.trim().match(/\d+\.\d+\.\d+/);
	return match ? match[0] : null;
}

/** Compare dotted versions: -1, 0 or 1. */
function compareVersions(a: string, b: string): number {
	const left = a.split(".").map((n) => parseInt(n, 10) || 0);
	const right = b.split(".").map((n) => parseInt(n, 10) || 0);
	for (let i = 0; i < Math.max(left.length, right.length); i++) {
		const diff = (left[i] ?? 0) - (right[i] ?? 0);
		if (diff !== 0) return diff < 0 ? -1 : 1;
	}
	return 0;
}

/** The last lines of the proxy's log, if it wrote any. */
function logTail(path: string, lines = 10): string {
	try {
		const text = readFileSync(path, "utf8").trimEnd();
		if (!text) return "";
		return text.split("\n").slice(-lines).join("\n");
	} catch {
		return "";
	}
}

function sanitizeSession(raw: string): string {
	const cleaned = (raw ?? "").replace(SESSION_RE, "-").slice(0, 64);
	return cleaned || "session";
}

function sanitizeCall(raw: string): string {
	return (raw ?? "").replace(CALL_RE, "-").slice(0, 96);
}

/** A free TCP port on the loopback interface. */
function freePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = createServer();
		server.on("error", reject);
		server.listen(0, "127.0.0.1", () => {
			const address = server.address();
			const port = typeof address === "object" && address ? address.port : 0;
			server.close(() => (port ? resolve(port) : reject(new Error("no free port"))));
		});
	});
}

type ApiInfo = { url: string; token: string; proxy: string };

/** The API description the proxy writes when it comes up. */
async function readApi(dataDir: string): Promise<ApiInfo | null> {
	const file = join(dataDir, "api.json");
	if (!existsSync(file)) return null;
	try {
		const parsed = JSON.parse(readFileSync(file, "utf8"));
		if (parsed && typeof parsed.url === "string" && typeof parsed.token === "string") {
			return { url: parsed.url, token: parsed.token, proxy: parsed.proxy ?? "" };
		}
	} catch {
		/* a half-written file: not up yet */
	}
	return null;
}

/** Wait for the proxy to write its api.json and answer on it. */
async function waitForApi(dataDir: string, timeoutMs: number): Promise<ApiInfo | null> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const info = await readApi(dataDir);
		if (info && (await apiAnswers(info.url))) return info;
		await new Promise((resolve) => setTimeout(resolve, 400));
	}
	return null;
}

async function apiAnswers(apiUrl: string): Promise<boolean> {
	try {
		const response = await fetch(`${apiUrl}/healthz`, { signal: AbortSignal.timeout(2000) });
		return response.ok;
	} catch {
		return false;
	}
}

async function stopProxy(scan: Scan | null) {
	if (!scan?.child) return;
	const child = scan.child;
	child.kill("SIGTERM");
	await new Promise((resolve) => {
		const timer = setTimeout(() => {
			child.kill("SIGKILL");
			resolve(undefined);
		}, 8000);
		child.on("exit", () => {
			clearTimeout(timer);
			resolve(undefined);
		});
	});
}

function run(command: string, args: string[]): Promise<{ stdout: string; stderr: string; code: number }> {
	return new Promise((resolve, reject) => {
		const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => (stdout += chunk));
		child.stderr.on("data", (chunk) => (stderr += chunk));
		child.on("error", reject);
		child.on("close", (code) => resolve({ stdout, stderr, code: code ?? 0 }));
	});
}
