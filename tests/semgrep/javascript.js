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
