// main.ts - Basic Token Allocation System for Deno Deploy (SHA-256 Hashing & Rate Limiting)

// Import necessary modules
// Using Deno.serve which is built-in and requires no external import for basic use.
// Using Deno's built-in Web Crypto API for hashing (SHA-256).

// Initialize Deno KV
// Deno KV is used for storing user data, transactions, and failed login attempts.
const kv = await Deno.openKv();

// --- Constants and Configuration ---
const BASIC_ALLOCATION_UNITS = 50;
const UNITS_TO_PARTS_MULTIPLIER = 1000;
const BASIC_ALLOCATION_PARTS = BASIC_ALLOCATION_UNITS * UNITS_TO_PARTS_MULTIPLIER; // 50000 parts

// Approximation of a month in milliseconds for monthly allocation check.
const ONE_MONTH_MS = 30 * 24 * 60 * 60 * 1000;

// Rate Limiting Configuration
const MAX_FAILED_ATTEMPTS = 5; // Maximum failed attempts before delay starts
const BASE_DELAY_MS = 1000; // 1 second base delay

// --- Helper Functions ---

// Generates a simple unique user ID based on username.
// NOTE: In a real system, this MUST be tied to a robust, verified identity process
// to ensure uniqueness per person globally. This is a simplification for the demo.
function generateUserId(username: string): string {
    return "user_" + username.toLowerCase().replace(/\s+/g, '_');
}

// Gets user data from KV using their user ID.
async function getUser(userId: string): Promise<any | null> {
    const user = await kv.get(["users", userId]);
    return user.value;
}

// Saves user data to KV.
async function saveUser(userId: string, userData: any): Promise<void> {
    await kv.set(["users", userId], userData);
}

// Gets transactions for a specific user from KV.
async function getUserTransactions(userId: string): Promise<any[]> {
    const iter = kv.list({ prefix: ["transactions", userId] });
    const transactions = [];
    for await (const entry of iter) {
        transactions.push(entry.value);
    }
    transactions.sort((a, b) => a.timestamp - b.timestamp);
    return transactions;
}

// Records a transaction in KV.
async function recordTransaction(fromUserId: string, toUserId: string, amountParts: number, type: 'allocation' | 'send' | 'receive'): Promise<void> {
    const transaction = {
        id: crypto.randomUUID(),
        from: fromUserId,
        to: toUserId,
        amount_parts: amountParts,
        type: type,
        timestamp: Date.now(),
    };
    await kv.set(["transactions", fromUserId, transaction.timestamp + "_out"], transaction);
    await kv.set(["transactions", toUserId, transaction.timestamp + "_in"], transaction);
}

// Generates a random salt for password hashing.
async function generateSalt(): Promise<Uint8Array> {
    return crypto.getRandomValues(new Uint8Array(16)); // 16 bytes is a common salt size
}

// Hashes a password using SHA-256 with a salt.
// Returns the salt and the hash.
async function hashPassword(password: string, salt: Uint8Array): Promise<string> {
    // Combine salt and password
    const textEncoder = new TextEncoder();
    const passwordBytes = textEncoder.encode(password);
    const saltedPassword = new Uint8Array(salt.length + passwordBytes.length);
    saltedPassword.set(salt, 0);
    saltedPassword.set(passwordBytes, salt.length);

    // Hash the salted password using SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', saltedPassword);

    // Convert the hash buffer to a hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Return the salt (as hex) and the hash (as hex), combined for storage
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    return saltHex + ':' + hashHex; // Store salt and hash separated by a colon
}

// Verifies a password against a stored salt and hash.
async function verifyPassword(password: string, storedSaltAndHash: string): Promise<boolean> {
    try {
        const [saltHex, storedHashHex] = storedSaltAndHash.split(':');
        if (!saltHex || !storedHashHex) return false;

        // Convert salt hex back to Uint8Array
        const salt = new Uint8Array(saltHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));

        // Hash the provided password with the stored salt
        const textEncoder = new TextEncoder();
        const passwordBytes = textEncoder.encode(password);
        const saltedPassword = new Uint8Array(salt.length + passwordBytes.length);
        saltedPassword.set(salt, 0);
saltedPassword.set(passwordBytes, salt.length);

        const hashBuffer = await crypto.subtle.digest('SHA-256', saltedPassword);

        // Convert the newly generated hash buffer to a hex string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const newHashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Compare the newly generated hash hex with the stored hash hex
        // Use a constant-time comparison if possible to prevent timing attacks,
        // but simple string comparison is acceptable for this demo's purpose.
        return newHashHex === storedHashHex;

    } catch (e) {
        console.error("Error during password verification:", e);
        return false; // Handle potential errors during verification
    }
}

// Gets failed login attempts data for a user.
async function getFailedAttempts(userId: string): Promise<{ count: number, lastAttempt: number } | null> {
    const result = await kv.get(["failed_login_attempts", userId]);
    return result.value;
}

// Sets failed login attempts data for a user.
async function setFailedAttempts(userId: string, count: number, lastAttempt: number): Promise<void> {
    await kv.set(["failed_login_attempts", userId], { count, lastAttempt });
}

// Clears failed login attempts data for a user.
async function clearFailedAttempts(userId: string): Promise<void> {
     await kv.delete(["failed_login_attempts", userId]);
}

// Calculates the required delay based on the number of failed attempts.
function calculateDelay(failedCount: number): number {
    if (failedCount <= MAX_FAILED_ATTEMPTS) {
        return 0; // No delay for first few attempts
    }
    // Exponential backoff: BASE_DELAY_MS * 2^(failedCount - MAX_FAILED_ATTEMPTS)
    const delay = BASE_DELAY_MS * Math.pow(2, failedCount - MAX_FAILED_ATTEMPTS);
    // Cap the delay to prevent excessively long waits (e.g., 1 minute max)
    return Math.min(delay, 60000); // Max 60 seconds delay
}

// Enforces a delay if required based on failed login attempts.
async function enforceDelay(userId: string): Promise<string | null> {
    const failedAttempts = await getFailedAttempts(userId);
    if (failedAttempts) {
        const requiredDelay = calculateDelay(failedAttempts.count);
        const timeSinceLastAttempt = Date.now() - failedAttempts.lastAttempt;

        if (timeSinceLastAttempt < requiredDelay) {
            const remainingDelay = requiredDelay - timeSinceLastAttempt;
            // Simulate waiting (in a real system, this might involve a blocking operation or returning a "Too Many Requests" response with a Retry-After header)
            // For this demo, we'll return a message and expect the user to wait before trying again.
            return `Too many failed login attempts. Please wait ${Math.ceil(remainingDelay / 1000)} seconds before trying again.`;
        } else {
            // If enough time has passed, clear the failed attempts count for this user.
            await clearFailedAttempts(userId);
            return null; // No delay needed
        }
    }
    return null; // No failed attempts recorded
}


// --- HTML Templates (Vanilla HTML) ---

function htmlLayout(title: string, content: string, user?: any): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>${title}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: sans-serif; line-height: 1.6; margin: 20px; }
        nav a { margin-right: 15px; }
        .container { max-width: 800px; margin: auto; }
        form div { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"], input[type="number"] {
            width: calc(100% - 22px); padding: 10px; border: 1px solid #ccc;
        }
        button { padding: 10px 15px; background-color: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .transaction { border-bottom: 1px solid #eee; padding: 10px 0; }
        .transaction:last-child { border-bottom: none; }
        .error { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>${title}</h1>
        <nav>
            <a href="/">Home</a>
            ${user ? `<a href="/dashboard">Dashboard</a> <a href="/logout">Logout</a>` : `<a href="/signup">Signup</a> <a href="/login">Login</a>`}
        </nav>
        <hr>
        ${content}
    </div>
</body>
</html>
`;
}

function homePageHTML(): string {
    return htmlLayout("Welcome to Diz (Basic Demo)", `
        <p>This is a simplified demonstration of the basic token allocation and transfer logic of the Diz system, built with Deno Deploy and Deno KV.</p>
        <p>It illustrates:</p>
        <ul>
            <li>User Signup with SHA-256 Hashing & Salting & Basic Allocation</li>
            <li>Monthly Allocation on Login (with secure password verification & rate limiting)</li>
            <li>Token Balance</li>
            <li>Sending Tokens to Others</li>
            <li>Basic Transaction History ("Transaction River")</li>
        </ul>
        <p>Note: This demo skips many crucial real-world complexities like true identity verification (essential for "each person on the planet"), robust session management beyond a simple cookie, complex error handling, and the full Functional Intelligence features described in the vision.</p>
        <p><a href="/signup">Sign up</a> or <a href="/login">Log in</a> to try the basic features.</p>
    `);
}

function signupFormHTML(error?: string): string {
    return htmlLayout("Signup", `
        <p>Create your account to receive your initial basic allowance.</p>
        ${error ? `<p class="error">${error}</p>` : ''}
        <form action="/signup" method="post">
            <div>
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
             <div>
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <button type="submit">Sign Up</button>
        </form>
    `);
}

function loginFormHTML(error?: string): string {
    return htmlLayout("Login", `
        <p>Log in to access your dashboard and receive your monthly allowance.</p>
        ${error ? `<p class="error">${error}</p>` : ''}
        <form action="/login" method="post">
            <div>
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
    `);
}

function dashboardHTML(user: any, transactions: any[], allocationMessage: string | null): string {
    const transactionListItems = transactions.map(tx => {
        const type = tx.type === 'allocation' ? 'Received Allocation'
                   : tx.from === user.id ? `Sent to ${tx.to.replace('user_', '')}`
                   : `Received from ${tx.from.replace('user_', '')}`;
        const amount = tx.amount_parts / UNITS_TO_PARTS_MULTIPLIER;
        const sign = tx.from === user.id ? '-' : '+';
        const date = new Date(tx.timestamp).toLocaleString();
        return `<div class="transaction"><strong>${type}:</strong> ${sign}${amount.toFixed(3)} units on ${date}</div>`;
    }).join('');

    return htmlLayout("Dashboard", `
        ${allocationMessage ? `<p style="color: green; font-weight: bold;">${allocationMessage}</p>` : ''}
        <h2>Your Account (${user.username})</h2>
        <p>Your Balance: <strong>${(user.balance_parts / UNITS_TO_PARTS_MULTIPLIER).toFixed(3)}</strong> units (${user.balance_parts} parts)</p>

        <h3>Send Allowance</h3>
        <form action="/send" method="post">
            <input type="hidden" name="fromUserId" value="${user.id}">
             <div>
                <label for="recipientUsername">Recipient Username:</label>
                <input type="text" id="recipientUsername" name="recipientUsername" required>
            </div>
            <div>
                <label for="amountUnits">Amount to Send (Units):</label>
                <input type="number" id="amountUnits" name="amountUnits" step="0.001" min="0.001" required>
                <small>Enter amount in units (e.g., 0.005 for 5 parts)</small>
            </div>
            <button type="submit">Send Tokens</button>
        </form>

        <h3>Transaction River</h3>
        <div id="transaction-list">
            ${transactionListItems.length > 0 ? transactionListItems : '<p>No transactions yet.</p>'}
        </div>
    `, user);
}

function sendResultHTML(message: string, success: boolean, user: any): string {
    return htmlLayout("Send Result", `
        <p style="color: ${success ? 'green' : 'red'}; font-weight: bold;">${message}</p>
        <p><a href="/dashboard">Go back to Dashboard</a></p>
    `, user);
}

// --- Request Handler ---

Deno.serve(async (req: Request): Promise<Response> => {
    const url = new URL(req.url);

    let userId = req.headers.get("cookie")?.split('; ').find(row => row.startsWith('user_id='))?.split('=')[1];
    let user = userId ? await getUser(userId) : null;
    let allocationMessage: string | null = null;


    if (url.pathname === "/" && req.method === "GET") {
        return new Response(homePageHTML(), {
            headers: { "content-type": "text/html" },
        });

    } else if (url.pathname === "/signup" && req.method === "GET") {
         if (user) return Response.redirect(new URL('/dashboard', req.url).toString(), 302);
        return new Response(signupFormHTML(), {
            headers: { "content-type": "text/html" },
        });

    } else if (url.pathname === "/signup" && req.method === "POST") {
        if (user) return Response.redirect(new URL('/dashboard', req.url).toString(), 302);

        const formData = await req.formData();
        const username = formData.get("username")?.toString();
        const password = formData.get("password")?.toString();
        const confirmPassword = formData.get("confirm_password")?.toString();

        if (!username || !password || !confirmPassword) {
             console.log("Signup Error: Missing username, password, or confirmation");
             return new Response(signupFormHTML("Username, password, and confirmation are required."), {
                headers: { "content-type": "text/html" }, status: 400
            });
        }
         if (password !== confirmPassword) {
             console.log("Signup Error: Passwords do not match");
             return new Response(signupFormHTML("Passwords do not match."), {
                headers: { "content-type": "text/html" }, status: 400
            });
        }

        const newUserId = generateUserId(username);

        try {
            const existingUser = await getUser(newUserId);

            if (existingUser) {
                 console.log(`Signup Error: Username '${username}' already exists`);
                 return new Response(signupFormHTML(`Username '${username}' already exists.`), {
                    headers: { "content-type": "text/html" }, status: 400
                });
            }

            // --- Password Handling: Generate Salt and Hash using SHA-256 ---
            const salt = await generateSalt();
            const hashedPassword = await hashPassword(password, salt);
            console.log("Signup: Password hashed successfully");
            // --- End of Password Handling ---

            user = {
                id: newUserId,
                username: username,
                password_hash: hashedPassword, // Store salt and hash
                balance_parts: BASIC_ALLOCATION_PARTS,
                last_allocation_timestamp: Date.now(),
            };
            await saveUser(user.id, user);
            console.log(`Signup: User '${username}' saved to KV`);

            await recordTransaction("system", user.id, BASIC_ALLOCATION_PARTS, 'allocation');
            console.log(`Signup: Initial allocation recorded for '${username}'`);

            const headers = new Headers();
            headers.set("content-type", "text/html");
            headers.set("Set-Cookie", `user_id=${user.id}; Path=/; HttpOnly`);
            console.log(`Signup: Cookie set for '${username}'. Redirecting to dashboard.`);

             return Response.redirect(new URL('/dashboard', req.url).toString(), 302);

        } catch (error) {
            console.error("Error during signup:", error);
            return new Response(htmlLayout("Error", `
                <p class="error">An internal server error occurred during signup. Please try again later.</p>
                <p><a href="/signup">Back to Signup</a></p>
            `), {
                headers: { "content-type": "text/html" },
                status: 500
            });
        }


    } else if (url.pathname === "/login" && req.method === "GET") {
         if (user) return Response.redirect(new URL('/dashboard', req.url).toString(), 302);
        return new Response(loginFormHTML(), {
            headers: { "content-type": "text/html" },
        });

    } else if (url.pathname === "/login" && req.method === "POST") {
         if (user) {
             console.log("Login POST: User already logged in, redirecting to dashboard.");
             return Response.redirect(new URL('/dashboard', req.url).toString(), 302);
         }

        const formData = await req.formData();
        const username = formData.get("username")?.toString();
        const password = formData.get("password")?.toString();

        if (!username || !password) {
             console.log("Login POST Error: Missing username or password");
             return new Response(loginFormHTML("Username and password are required."), {
                headers: { "content-type": "text/html" }, status: 400
            });
        }

        const loginUserId = generateUserId(username);
        console.log(`Login POST: Attempting login for user ID: ${loginUserId}`);

        try {
            // --- Rate Limiting Check ---
            console.log("Login POST: Checking rate limit...");
            const delayMessage = await enforceDelay(loginUserId);
            if (delayMessage) {
                 console.log(`Login POST: Rate limit enforced for ${loginUserId}. Message: ${delayMessage}`);
                 // If a delay is enforced, record the failed attempt and return the message.
                 // Note: Recording failed attempts happens *after* checking delay to avoid
                 // immediately increasing delay for the current request if it's already delayed.
                 const failedAttempts = await getFailedAttempts(loginUserId) || { count: 0, lastAttempt: 0 };
                 await setFailedAttempts(loginUserId, failedAttempts.count + 1, Date.now());
                 return new Response(loginFormHTML(delayMessage), {
                    headers: { "content-type": "text/html" }, status: 429 // Too Many Requests
                });
            }
            console.log("Login POST: Rate limit check passed.");
            // --- End of Rate Limiting Check ---


            user = await getUser(loginUserId);
            console.log(`Login POST: User data fetched for ${loginUserId}:`, user ? 'Found' : 'Not Found');


            if (!user) {
                 console.log(`Login POST Error: User '${username}' not found.`);
                 // If user not found, record a failed attempt before returning error.
                 const failedAttempts = await getFailedAttempts(loginUserId) || { count: 0, lastAttempt: 0 };
                 await setFailedAttempts(loginUserId, failedAttempts.count + 1, Date.now());
                return new Response(loginFormHTML("Invalid username or password."), {
                    headers: { "content-type": "text/html" }, status: 401
                });
            }

            // --- Password Verification: Compare password against the stored hash ---
            console.log("Login POST: Verifying password...");
            const passwordMatch = await verifyPassword(password, user.password_hash);
            console.log(`Login POST: Password match result: ${passwordMatch}`);

            if (!passwordMatch) {
                console.log(`Login POST Error: Password mismatch for user '${username}'.`);
                // If password doesn't match, record a failed attempt before returning error.
                 const failedAttempts = await getFailedAttempts(loginUserId) || { count: 0, lastAttempt: 0 };
                 await setFailedAttempts(loginUserId, failedAttempts.count + 1, Date.now());
                return new Response(loginFormHTML("Invalid username or password."), {
                    headers: { "content-type": "text/html" }, status: 401
                });
            }
             // --- End of Password Verification ---

            // If login is successful, clear any failed attempt records for this user.
            console.log(`Login POST: Login successful for user '${username}'. Clearing failed attempts.`);
            await clearFailedAttempts(loginUserId);


            // Check for monthly allocation on first login of the month.
            if (Date.now() - user.last_allocation_timestamp > ONE_MONTH_MS) {
                console.log(`Login POST: Monthly allocation due for user '${username}'.`);
                user.balance_parts += BASIC_ALLOCATION_PARTS;
                user.last_allocation_timestamp = Date.now();
                await saveUser(user.id, user);
                await recordTransaction("system", user.id, BASIC_ALLOCATION_PARTS, 'allocation');
                allocationMessage = "Monthly allowance received!";
                 console.log(`Login POST: Monthly allocation granted and recorded for '${username}'.`);
            } else {
                 console.log(`Login POST: Monthly allocation not due for user '${username}'.`);
            }

            // Set a cookie to keep the user logged in for this demo session.
            const headers = new Headers();
            headers.set("content-type", "text/html");
            headers.set("Set-Cookie", `user_id=${user.id}; Path=/; HttpOnly`);
            console.log(`Login POST: Cookie set for user '${username}'.`);


             const redirectUrl = new URL('/dashboard', req.url);
             if(allocationMessage) redirectUrl.searchParams.set('msg', encodeURIComponent(allocationMessage));
             // --- Successful Login: Redirect to Dashboard ---
             console.log(`Login POST: Redirecting to dashboard for user '${username}'.`);
             return Response.redirect(redirectUrl.toString(), 302);
             // --- End of Redirect ---

        } catch (error) {
             console.error("Error during login:", error);
            return new Response(htmlLayout("Error", `
                <p class="error">An internal server error occurred during login. Please try again later.</p>
                <p><a href="/login">Back to Login</a></p>
            `), {
                headers: { "content-type": "text/html" },
                status: 500
            });
        }


    } else if (url.pathname === "/logout" && req.method === "GET") {
        console.log("Logout: Clearing cookie and redirecting to home.");
        const headers = new Headers();
        headers.set("Set-Cookie", `user_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
        headers.set("location", "/");
        return new Response(null, { status: 302, headers });

    } else if (url.pathname === "/dashboard" && req.method === "GET") {
        if (!user) {
            console.log("Dashboard GET: Not logged in, redirecting to login.");
            return Response.redirect(new URL('/login', req.url).toString(), 302);
        }
        console.log(`Dashboard GET: User '${user.username}' accessing dashboard.`);

        try {
            const transactions = await getUserTransactions(user.id);
            console.log(`Dashboard GET: Fetched ${transactions.length} transactions for '${user.username}'.`);

            const msg = url.searchParams.get('msg');
            if (msg) allocationMessage = decodeURIComponent(msg);

            return new Response(dashboardHTML(user, transactions, allocationMessage), {
                headers: { "content-type": "text/html" },
            });
        } catch (error) {
             console.error("Error fetching transactions:", error);
             return new Response(htmlLayout("Error", `
                <p class="error">An internal server error occurred while loading your dashboard.</p>
                <p><a href="/">Go to Home</a></p>
            `), {
                headers: { "content-type": "text/html" },
                status: 500
            });
        }


    } else if (url.pathname === "/send" && req.method === "POST") {
        if (!user) {
             console.log("Send POST: Not logged in, redirecting to login.");
             return Response.redirect(new URL('/login', req.url).toString(), 302);
        }
         console.log(`Send POST: User '${user.username}' attempting to send tokens.`);

        const formData = await req.formData();
        const recipientUsername = formData.get("recipientUsername")?.toString();
        const amountUnits = parseFloat(formData.get("amountUnits")?.toString() || '0');
        const amountParts = Math.round(amountUnits * UNITS_TO_PARTS_MULTIPLIER);

        let message = "";
        let success = false;

        if (!recipientUsername || amountUnits <= 0 || !Number.isInteger(amountParts) || amountParts <= 0) {
            message = "Invalid recipient or amount.";
             console.log(`Send POST Error: ${message}`);
        } else {
            try {
                const recipientUserId = generateUserId(recipientUsername);
                 console.log(`Send POST: Recipient user ID: ${recipientUserId}`);
                const recipient = await getUser(recipientUserId);
                 console.log(`Send POST: Recipient data fetched:`, recipient ? 'Found' : 'Not Found');


                if (!recipient) {
                    message = `Recipient '${recipientUsername}' not found.`;
                     console.log(`Send POST Error: ${message}`);
                }
                else if (user.balance_parts < amountParts) {
                    message = `Insufficient balance. You have ${(user.balance_parts / UNITS_TO_PARTS_MULTIPLIER).toFixed(3)} units.`;
                     console.log(`Send POST Error: ${message}`);
                } else {
                    // --- Perform the Token Transfer ---
                    console.log(`Send POST: Attempting atomic transfer of ${amountParts} parts from '${user.username}' to '${recipientUsername}'.`);
                    user.balance_parts -= amountParts;
                    recipient.balance_parts += amountParts;

                    const ok = await kv.atomic()
                        .mutate(
                            { key: ["users", user.id], value: user },
                            { key: ["users", recipient.id], value: recipient }
                        )
                        .commit();
                    console.log(`Send POST: Atomic commit result: ${ok.ok}`);


                    if (ok.ok) {
                        await recordTransaction(user.id, recipient.id, amountParts, 'send');
                        message = `Successfully sent ${amountUnits.toFixed(3)} units to ${recipientUsername}.`;
                        success = true;
                         console.log(`Send POST: Transaction successful: ${message}`);
                    } else {
                        message = "Transaction failed (atomic commit error).";
                         console.log(`Send POST Error: ${message}`);
                    }
                }
            } catch (error) {
                 console.error("Error during send:", error);
                message = "An internal server error occurred during the transaction.";
            }
        }

        return new Response(sendResultHTML(message, success, user), {
            headers: { "content-type": "text/html" },
        });


    } else {
        console.log(`Handler: 404 Not Found for path: ${url.pathname}`);
        return new Response(htmlLayout("Not Found", `
            <p>The page you requested could not be found.</p>
            <p><a href="/">Go to Home</a></p>
        `), {
            status: 404,
            headers: { "content-type": "text/html" },
        });
    }
});
