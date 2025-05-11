// Log a message to the Deno Deploy logs when the script starts
console.log("Simple handler function starting...");

// Start the HTTP server using Deno.serve
// It listens for incoming requests and calls the provided handler function
Deno.serve(async (request) => {
  // Get the requested URL path
  const url = new URL(request.url);
  console.log(`Request received for: ${url.pathname}`); // Log the requested path

  // Return a simple text response
  return new Response("Hello from Super Simple Deno Deploy!");
});

// Log another message after the server is started (this runs immediately after Deno.serve is called)
console.log("Simple server started.");
