// main.ts - Basic Token Allocation System for Deno Deploy (with Secure Password Hashing)

// Import necessary modules
// Using Deno.serve which is built-in and requires no external import for basic use.
// Importing bcrypt for secure password hashing.
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";

// Initialize Deno KV
// Deno KV is used for storing user data and transactions.
const kv = await Deno.openKv();

// --- Constants and Configuration ---
const BASIC_ALLOCATION_UNITS = 50;
const UNITS_TO_PARTS_MULTIPLIER = 1000;
const BASIC_ALLOCATION_PARTS = BASIC_ALLOCATION_UNITS * UNITS_TO_PARTS_MULTIPLIER; // 50000 parts

// Approximation of a month in milliseconds for monthly allocation check.
// In a real system, this would ideally be tied to calendar months for accuracy.
const ONE_MONTH_MS = 30 * 24 * 60 * 60 * 1000;

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
// Transactions are stored indexed by user ID and timestamp for retrieval.
async function getUserTransactions(userId: string): Promise<any[]> {
    // List all transactions with the prefix for this user ID.
    const iter = kv.list({ prefix: ["transactions", userId] });
    const transactions = [];
    for await (const entry of iter) {
        transactions.push(entry.value);
    }
    // Sort transactions by timestamp to ensure chronological order for the "river" display.
    transactions.sort((a, b) => a.timestamp - b.timestamp);
    return transactions;
}

// Records a transaction in KV.
// A transaction object is stored for both the sender and recipient (if applicable)
// to facilitate easy retrieval for both users' transaction history.
async function recordTransaction(fromUserId: string, toUserId: string, amountParts: number, type: 'allocation' | 'send' | 'receive'): Promise<void> {
    const transaction = {
        id: crypto.randomUUID(), // Unique transaction ID
        from: fromUserId, // User ID the tokens came from ('system' for allocation)
        to: toUserId,   // User ID the tokens went to
        amount_parts: amountParts, // Amount in the smallest unit (parts)
        type: type, // Type of transaction ('allocation', 'send', 'receive')
        timestamp: Date.now(), // Timestamp for ordering - simulates "appended to stack"
        // In a real system, this would be a serialized Protocol Buffer binary data.
        // For this demo, it's a JS object stored in KV.
    };

    // Store the transaction, indexed by the 'from' user and timestamp.
    await kv.set(["transactions", fromUserId, transaction.timestamp + "_out"], transaction);
    // Store the transaction, indexed by the 'to' user and timestamp.
    await kv.set(["transactions", toUserId, transaction.timestamp + "_in"], transaction);
}

// --- HTML Templates (Vanilla HTML) ---
// These functions generate the HTML strings for different pages.

function htmlLayout(title: string, content: string, user?: any): string {
    // Basic HTML structure and styling.
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
        <p>This version demonstrates **proper password hashing** for signup and login, addressing the crucial security concern from the previous example.</p>
        <p>It illustrates:</p>
        <ul>
            <li>User Signup with Secure Password Hashing & Basic Allocation</li>
            <li>Monthly Allocation on Login (with secure password verification)</li>
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
    // Generates the HTML list for the transaction river.
    const transactionListItems = transactions.map(tx => {
        const type = tx.type === 'allocation' ? 'Received Allocation'
                   : tx.from === user.id ? `Sent to ${tx.to.replace('user_', '')}`
                   : `Received from ${tx.from.replace('user_', '')}`;
        const amount = tx.amount_parts / UNITS_TO_PARTS_MULTIPLIER;
        const sign = tx.from === user.id ? '-' : '+'; // Indicate if tokens were sent (-) or received (+) by the current user
        const date = new Date(tx.timestamp).toLocaleString(); // Format timestamp for display
        return `<div class="transaction"><strong>${type}:</strong> ${sign}${amount.toFixed(3)} units on ${date}</div>`;
    }).join(''); // Join all transaction HTML strings

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
// This function handles all incoming HTTP requests.

Deno.serve(async (req: Request): Promise<Response> => {
    const url = new URL(req.url);

    // Basic session management using a cookie.
    // In a real system, use more secure session tokens/management.
    let userId = req.headers.get("cookie")?.split('; ').find(row => row.startsWith('user_id='))?.split('=')[1];
    let user = userId ? await getUser(userId) : null;
    let allocationMessage: string | null = null; // Message for monthly allocation display


    // --- Handle Different Routes and HTTP Methods ---

    if (url.pathname === "/" && req.method === "GET") {
        // Serve the home page.
        return new Response(homePageHTML(), {
            headers: { "content-type": "text/html" },
        });

    } else if (url.pathname === "/signup" && req.method === "GET") {
         // Serve the signup form. Redirect to dashboard if already logged in.
         if (user) return Response.redirect(new URL('/dashboard', req.url).toString(), 302);
        return new Response(signupFormHTML(), {
            headers: { "content-type": "text/html" },
        });

    } else if (url.pathname === "/signup" && req.method === "POST") {
        // Handle signup form submission.
        if (user) return Response.redirect(new URL('/dashboard', req.url).toString(), 302);

        const formData = await req.formData();
        const username = formData.get("username")?.toString();
        const password = formData.get("password")?.toString();
        const confirmPassword = formData.get("confirm_password")?.toString();

        // Basic input validation.
        if (!username || !password || !confirmPassword) {
             return new Response(signupFormHTML("Username, password, and confirmation are required."), {
                headers: { "content-type": "text/html" }, status: 400
            });
        }
         if (password !== confirmPassword) {
             return new Response(signupFormHTML("Passwords do not match."), {
                headers: { "content-type": "text/html" }, status: 400
            });
        }

        const newUserId = generateUserId(username);
        const existingUser = await getUser(newUserId);

        // Check if username already exists.
        if (existingUser) {
             return new Response(signupFormHTML(`Username '${username}' already exists.`), {
                headers: { "content-type": "text/html" }, status: 400
            });
        }

        // --- Secure Password Handling: Hash the password ---
        // Use bcrypt to hash the user's password before storing it.
        const hashedPassword = await bcrypt.hash(password);
        // --- End of Secure Handling ---

        // Create the new user object.
        user = {
            id: newUserId,
            username: username,
            password_hash: hashedPassword, // Store the hash, NOT the plaintext password.
            balance_parts: BASIC_ALLOCATION_PARTS, // Allocate initial basic needs tokens.
            last_allocation_timestamp: Date.now(), // Record time of first allocation.
        };
        await saveUser(user.id, user); // Save the new user to KV.

        // Record the initial allocation transaction from the system.
        await recordTransaction("system", user.id, BASIC_ALLOCATION_PARTS, 'allocation');

        // Set a cookie to keep the user logged in for this demo session.
        const headers = new Headers();
        headers.set("content-type", "text/html");
        headers.set("Set-Cookie", `user_id=${user.id}; Path=/; HttpOnly`);

        // Redirect the user to the dashboard after successful signup.
         return Response.redirect(new URL('/dashboard', req.url).toString(), 302);


    } else if (url.pathname === "/login" && req.method === "GET") {
         // Serve the login form. Redirect to dashboard if already logged in.
         if (user) return Response.redirect(new URL('/dashboard', req.url).toString(), 302);
        return new Response(loginFormHTML(), {
            headers: { "content-type": "text/html" },
        });

    } else if (url.pathname === "/login" && req.method === "POST") {
         // Handle login form submission.
         if (user) return Response.redirect(new URL('/dashboard', req.url).toString(), 302);

        const formData = await req.formData();
        const username = formData.get("username")?.toString();
        const password = formData.get("password")?.toString();

        // Basic input validation.
        if (!username || !password) {
             return new Response(loginFormHTML("Username and password are required."), {
                headers: { "content-type": "text/html" }, status: 400
            });
        }

        const loginUserId = generateUserId(username);
        user = await getUser(loginUserId);

        // Check if user exists.
        if (!user) {
            return new Response(loginFormHTML("Invalid username or password."), {
                headers: { "content-type": "text/html" }, status: 401
            });
        }

        // --- Secure Password Handling: Compare password against the stored hash ---
        // Use bcrypt.compare to securely verify the submitted password against the stored hash.
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        // If passwords do not match, return an error.
        if (!passwordMatch) {
            return new Response(loginFormHTML("Invalid username or password."), {
                headers: { "content-type": "text/html" }, status: 401
            });
        }
         // --- End of Secure Handling ---

        // Check for monthly allocation on first login of the month.
        // If enough time has passed since the last allocation, add the basic allocation.
        if (Date.now() - user.last_allocation_timestamp > ONE_MONTH_MS) {
            user.balance_parts += BASIC_ALLOCATION_PARTS;
            user.last_allocation_timestamp = Date.now();
            await saveUser(user.id, user); // Save the updated user data.
            await recordTransaction("system", user.id, BASIC_ALLOCATION_PARTS, 'allocation'); // Record the allocation transaction.
            allocationMessage = "Monthly allowance received!"; // Set message for dashboard display.
        }

        // Set a cookie to keep the user logged in for this demo session.
        const headers = new Headers();
        headers.set("content-type", "text/html");
        headers.set("Set-Cookie", `user_id=${user.id}; Path=/; HttpOnly`);

         // Redirect to the dashboard after successful login.
         // Pass the allocation message via URL parameter for simplicity in this demo.
         const redirectUrl = new URL('/dashboard', req.url);
         if(allocationMessage) redirectUrl.searchParams.set('msg', encodeURIComponent(allocationMessage));
         return Response.redirect(redirectUrl.toString(), 302);


    } else if (url.pathname === "/logout" && req.method === "GET") {
        // Handle user logout by clearing the cookie and redirecting to home.
        const headers = new Headers();
        headers.set("Set-Cookie", `user_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`); // Clear the user_id cookie.
        headers.set("location", "/"); // Redirect to the home page.
        return new Response(null, { status: 302, headers });

    } else if (url.pathname === "/dashboard" && req.method === "GET") {
        // Serve the user dashboard. Redirect to login if not logged in.
        if (!user) return Response.redirect(new URL('/login', req.url).toString(), 302);

        // Fetch the user's transaction history for the "Transaction River".
        const transactions = await getUserTransactions(user.id);

        // Check for allocation message passed from login redirect URL parameter.
        const msg = url.searchParams.get('msg');
        if (msg) allocationMessage = decodeURIComponent(msg);

        // Serve the dashboard HTML with user data and transactions.
        return new Response(dashboardHTML(user, transactions, allocationMessage), {
            headers: { "content-type": "text/html" },
        });

    } else if (url.pathname === "/send" && req.method === "POST") {
        // Handle sending tokens between users. Redirect to login if not logged in.
        if (!user) return Response.redirect(new URL('/login', req.url).toString(), 302);

        const formData = await req.formData();
        const recipientUsername = formData.get("recipientUsername")?.toString();
        const amountUnits = parseFloat(formData.get("amountUnits")?.toString() || '0');
        // Convert the amount from units to the smallest unit (parts).
        const amountParts = Math.round(amountUnits * UNITS_TO_PARTS_MULTIPLIER);

        let message = "";
        let success = false;

        // Validate recipient and amount.
        if (!recipientUsername || amountUnits <= 0 || !Number.isInteger(amountParts) || amountParts <= 0) {
            message = "Invalid recipient or amount.";
        } else {
            const recipientUserId = generateUserId(recipientUsername);
            const recipient = await getUser(recipientUserId);

            // Check if recipient exists.
            if (!recipient) {
                message = `Recipient '${recipientUsername}' not found.`;
            }
            // Check if sender has sufficient balance.
            else if (user.balance_parts < amountParts) {
                message = `Insufficient balance. You have ${(user.balance_parts / UNITS_TO_PARTS_MULTIPLIER).toFixed(3)} units.`;
            } else {
                // --- Perform the Token Transfer ---
                // Deduct from sender and add to recipient.
                user.balance_parts -= amountParts;
                recipient.balance_parts += amountParts;

                // Use a KV atomic transaction to ensure both balance updates succeed or fail together.
                const ok = await kv.atomic()
                    .mutate(
                        { key: ["users", user.id], value: user },
                        { key: ["users", recipient.id], value: recipient }
                    )
                    .commit();

                if (ok.ok) {
                    // If the atomic update was successful, record the transaction for both users.
                    await recordTransaction(user.id, recipient.id, amountParts, 'send');
                    message = `Successfully sent ${amountUnits.toFixed(3)} units to ${recipientUsername}.`;
                    success = true;
                } else {
                    // Handle atomic commit failure.
                    message = "Transaction failed (atomic commit error).";
                }
            }
        }

        // Serve the result page indicating success or failure of the send operation.
        return new Response(sendResultHTML(message, success, user), {
            headers: { "content-type": "text/html" },
        });


    } else {
        // Handle 404 Not Found for any other requested paths.
        return new Response(htmlLayout("Not Found", `
            <p>The page you requested could not be found.</p>
            <p><a href="/">Go to Home</a></p>
        `), {
            status: 404,
            headers: { "content-type": "text/html" },
        });
    }
});

