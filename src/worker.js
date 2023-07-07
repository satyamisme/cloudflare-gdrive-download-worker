// Cloudflare Worker script to download files from Google Drive API

addEventListener("fetch", async (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === "/download.aspx") {
    const fileId = url.searchParams.get("fileId");
    const accessToken = "YOUR_ACCESS_TOKEN"; // Replace with your Google Drive API access token

    if (fileId) {
      // Make a request to the Google Drive API to get the file download URL
      const fileUrl = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;
      const headers = { Authorization: `Bearer ${accessToken}` };
      const response = await fetch(fileUrl, { headers });

      // Check if the API request was successful
      if (response.ok) {
        // Get the content type from the response headers
        const contentType = response.headers.get("content-type");

        // Set the content type in the response headers
        const headers = { "content-type": contentType };

        // Return the file content as the response body
        return new Response(response.body, { headers });
      }
    }
    // If the file ID is missing or the API request failed, return an error response
    return new Response("Failed to download file", { status: 500 });
  }

  // For any other path, return an "OK" status
  return new Response("OK", { status: 200 });
}
