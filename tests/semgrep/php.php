<?php
// Synthetic static-analysis fixtures, never executed.

// ruleid: raw-sql-with-variables
DB::select("SELECT * FROM users WHERE email = '" . $email . "'");
// ruleid: raw-sql-with-variables
$query->whereRaw("status = $status");
// ruleid: raw-sql-with-variables
DB::statement("DROP TABLE " . $table);
// ruleid: raw-sql-with-variables
$pdo->query("SELECT * FROM orders WHERE id = {$id}");
// ok: raw-sql-with-variables
DB::select("SELECT * FROM users WHERE email = ?", [$email]);
// ok: raw-sql-with-variables
$query->whereRaw("status = ?", [$status]);
// ok: raw-sql-with-variables
DB::table('users')->where('email', $email)->first();

// ruleid: shell-command-with-variables
exec("convert " . $path . " out.png");
// ruleid: shell-command-with-variables
shell_exec($command);
// ruleid: shell-command-with-variables
system("ping -c 1 " . $request->input('host'));
// ok: shell-command-with-variables
exec("php artisan queue:restart");
// ok: shell-command-with-variables
exec("convert " . escapeshellarg($path) . " out.png");

// ruleid: upload-keeps-client-filename
$request->file('avatar')->move(public_path('uploads'), $request->file('avatar')->getClientOriginalName());
// ruleid: upload-keeps-client-filename
$file->storeAs('documents', $file->getClientOriginalName());
// ruleid: upload-keeps-client-filename
move_uploaded_file($_FILES['doc']['tmp_name'], 'uploads/' . $_FILES['doc']['name']);
// ok: upload-keeps-client-filename
$file->store('documents');
// ok: upload-keeps-client-filename
$file->storeAs('documents', $file->hashName());

$config = [
    // ruleid: hardcoded-secret-in-config
    'password' => 'Sup3rS3cretPassw0rd', // gitleaks:allow (deliberate fake for rule tests)
    // ruleid: hardcoded-secret-in-config
    'api_key' => 'sk_live_51Hc8xYzExampleKey', // gitleaks:allow (deliberate fake for rule tests)
    // ok: hardcoded-secret-in-config
    'password' => env('DB_PASSWORD'),
    // ok: hardcoded-secret-in-config
    'password' => 'required|min:8|confirmed',
    // ok: hardcoded-secret-in-config
    'password' => 'The provided password is incorrect.',
    // ok: hardcoded-secret-in-config
    'password' => '',
    // ok: hardcoded-secret-in-config
    'token' => 'required',
    // ok: hardcoded-secret-in-config
    'password' => 'パスワードが正しくありません',
];
// ruleid: hardcoded-secret-in-config
$token = 'ghp_ExampleTokenValue1234567890'; // gitleaks:allow (deliberate fake for rule tests)
// ok: hardcoded-secret-in-config
$token = $request->bearerToken();

$app = [
    // ruleid: debug-mode-hardcoded-on
    'debug' => true,
];
$app = [
    // ok: debug-mode-hardcoded-on
    'debug' => (bool) env('APP_DEBUG', false),
];
