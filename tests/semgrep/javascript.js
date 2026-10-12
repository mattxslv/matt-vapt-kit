// Synthetic static-analysis fixtures, never executed.
// ruleid: tls-verification-disabled
const insecure = { rejectUnauthorized: false };
// ok: tls-verification-disabled
const secure = { rejectUnauthorized: true };

// ruleid: dynamic-code-evaluation
eval(userInput);
// ok: dynamic-code-evaluation
JSON.parse(userInput);

// ruleid: shell-exec-with-template
exec(`echo ${userInput}`);
// ok: shell-exec-with-template
execFile("echo", [userInput]);

// ruleid: console-log-statement
console.log("debugging value", value);
// ruleid: console-log-statement
console.debug("trace");
// ruleid: console-log-statement
console.info("info message");
// ok: console-log-statement
console.error("real error, kept intentionally");
// ok: console-log-statement
console.warn("real warning, kept intentionally");
// ok: console-log-statement
logger.info("structured logger call, not console");

// ruleid: console-log-statement,console-emoji-debug
console.log("🚀 starting server", port);
// ruleid: console-emoji-debug
console.error("✅ done processing");
// ok: console-emoji-debug
console.error("payment failed for order", orderId);
