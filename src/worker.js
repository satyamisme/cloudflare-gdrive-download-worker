// Cloudflare Worker script to download files from Google Drive API

const serviceaccounts = [{
	"type": "service_account",
	"project_id": "XXXXXXXXXXX",
	"private_key_id": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	"private_key": "-----BEGIN PRIVATE KEY-----\XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n-----END PRIVATE KEY-----\n",
	"client_email": "XXXXXXXXX@XXXXXXXXXX.iam.gserviceaccount.com",
	"client_id": "113448625813676440808",
	"auth_uri": "https://accounts.google.com/o/oauth2/auth",
	"token_uri": "https://oauth2.googleapis.com/token",
	"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
	"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/XXXXXXXXXXXXXXXXXXXXXX.iam.gserviceaccount.com",
	"universe_domain": "googleapis.com"
}]; // This is a Example Service Account, generate your own using Google Cloud Console
const authConfig = {
	"client_id": "", // Client id from Google Cloud Console
	"client_secret": "", // Client Secret from Google Cloud Console
	"refresh_token": "", // Authorize token
	"service_account": true, // true if you're using Service Account instead of user account
	"service_account_json": serviceaccounts[Math.floor(Math.random() * serviceaccounts.length)], // don't touch this one
	"allow_direct_id_downloads": true, // true if you want to allow direct downloads using file id
	"allow_fetching_file_info": true, // true if you want to allow fetching file info using file id
	"allow_generating_links": true, // true if you want to allow generating links using file id
	"file_link_expiry": 7, // file link expiry in days 
}
const crypto_base_key = "3225f86e99e205347b4310e437253bfd" // Example 256 bit key used, generate your own.
const encrypt_iv = new Uint8Array([247, 254, 106, 195, 32, 148, 131, 244, 222, 133, 26, 182, 20, 138, 215, 81]); // Example 128 bit IV used, generate your own.

addEventListener('fetch', event => {
  event.respondWith(
    handleRequest(event.request, event).catch(err =>
      new Response("This is an error for the Site Owner Only ===> "+err.stack, { status: 500 })
    )
  );
});


async function handleRequest(request) {
	const url = new URL(request.url);
	const path = url.pathname;

  if (path === "/") {
    return new Response(html, {
      headers: {
        "content-type": "text/html;charset=UTF-8",
      },
    });
  } else if (path === "/download.aspx") {
		try {
			const file = await decryptString(url.searchParams.get('file'));
			const expiry = await decryptString(url.searchParams.get('expiry'));
			const integrity = await genIntegrity(`${file}|${expiry}`);
			const mac = url.searchParams.get('mac');
			const integrity_result = await checkintegrity(mac, integrity);
			const current_time = Math.floor(Date.now() / 1000);
			if (current_time > parseInt(expiry)) {
				return error_page("Link expired.");
			}
			if (integrity_result) {
				let range = request.headers.get('Range');
				const inline = 'true' === url.searchParams.get('inline');
				console.log(file, range)
				return download(file, range, inline);
			} else {
				return error_page("Integrity check failed.");
			}
		} catch (err) {
			return error_page("Invalid request.");
		}

	} else if (path === "/direct.aspx" && authConfig.allow_direct_id_downloads) {
		try {
			const file = url.searchParams.get('id');
			let range = request.headers.get('Range');
			const inline = 'true' === url.searchParams.get('inline');
			return download(file, range, inline);
		} catch (err) {
			return error_page("Invalid request.");
		}
	} else if (path === "/info.aspx" && authConfig.allow_fetching_file_info) {
		try {
			const file = url.searchParams.get('id');
			const pretty_print = 'true' === url.searchParams.get('pretty');
			const info = await getFileInfo(file);
			return new Response(pretty_print ? JSON.stringify(info, null, 2) : JSON.stringify(info), {
				headers: {
					"content-type": "application/json;charset=UTF-8",
          "Access-Control-Allow-Origin": "*", // Required for CORS support to work
				},
			});
		} catch (err) {
			return error_page("Invalid request.");
		}
	} else if (path === "/generate.aspx" && authConfig.allow_generating_links) {
		try {
			const file = url.searchParams.get('id');
			const pretty_print = 'true' === url.searchParams.get('pretty');
			const link = await generateLink(file);
			const json = {
				"link": "https://" + url.hostname + link
			}
			return new Response(pretty_print ? JSON.stringify(json, null, 2) : JSON.stringify(json), {
        status: 200,
				headers: {
					"content-type": "application/json;charset=UTF-8",
          "Access-Control-Allow-Origin": "*", // Required for CORS support to work
				},
			});
		} catch (e) {
			return error_page("Invalid request." + e);
		}
	} else if (path === "/generate_web_crypto.aspx") {
		const key = await generateAndReturnKey();
		const iv = await generateAndReturnIV();
		const json = {
			"key": key,
			"iv": iv
		}
		return new Response(JSON.stringify(json, null, 2), {
      status: 200,
			headers: {
				"content-type": "text/plain;charset=UTF-8",
        "Access-Control-Allow-Origin": "*", // Required for CORS support to work
			},
		});
	}

	// For any other path, return an "OK" status
	return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html;charset=UTF-8",
      "Access-Control-Allow-Origin": "*", // Required for CORS support to work
    },
  });
}

// error page response
function error_page(error) {
	const error_page_html = `
    <!DOCTYPE html>
    <html>
    <head>
    <title>${error}</title>
    </head>
    <body>
    <center><h1>${error}</h1></center>
    <hr><center>nginx</center>
    </body>
    </html>
    `;
	return new Response(error_page_html, {
		status: 401,
		headers: {
			"content-type": "text/html;charset=UTF-8",
      "Access-Control-Allow-Origin": "*", // Required for CORS support to work
		},
	})
}

// Web Crypto Encrypt API
async function encryptString(string) {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(crypto_base_key),
		"AES-CBC",
		false,
		["encrypt"]
	);
	const encodedId = new TextEncoder().encode(string);
	const encryptedData = await crypto.subtle.encrypt({
			name: "AES-CBC",
			iv: encrypt_iv
		},
		key,
		encodedId
	);
	const encryptedString = btoa(Array.from(new Uint8Array(encryptedData), (byte) => String.fromCharCode(byte)).join(""));
	return encryptedString;
}

// Web Crypto Decrypt API
async function decryptString(encryptedString) {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(crypto_base_key),
		"AES-CBC",
		false,
		["decrypt"]
	);
	const encryptedBytes = Uint8Array.from(atob(encryptedString), (char) => char.charCodeAt(0));
	const decryptedData = await crypto.subtle.decrypt({
			name: "AES-CBC",
			iv: encrypt_iv
		},
		key,
		encryptedBytes
	);
	const decryptedString = new TextDecoder().decode(decryptedData);
	return decryptedString;
}

// Web Crypto Integrity Generate API
async function genIntegrity(data) {
	const encoder = new TextEncoder();
	const dataBuffer = encoder.encode(data);

	const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);

	// Convert the hash buffer to hexadecimal string
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

	return hashHex;
}

// Web Crypto Integrity Check API
async function checkintegrity(text1, text2) {
	const hash1 = await genIntegrity(text1);
	const hash2 = await genIntegrity(text2);

	return hash1 === hash2;
}

// Web Crypto Link Generate API
async function generateLink(file_id) {
	const encrypted_id = await encryptString(file_id);
	const expiry = Date.now() + 1000 * 60 * 60 * 24 * authConfig.file_link_expiry;
	const encrypted_expiry = await encryptString(expiry.toString());
	const integrity = await genIntegrity(`${file_id}|${expiry}`);
	const url = `/download.aspx?file=${encodeURIComponent(encrypted_id)}&expiry=${encodeURIComponent(encrypted_expiry)}&mac=${encodeURIComponent(integrity)}`;
	return url;
}

// Web Crypto Key Generation API
async function generateKey() {
	const key = await crypto.subtle.generateKey({
			name: 'AES-CBC',
			length: 128
		},
		true,
		['encrypt', 'decrypt']
	);

	return key;
}

async function generateAndReturnKey() {
	const key = await generateKey();
	const keyBytes = await crypto.subtle.exportKey('raw', key);
	const keyHex = Array.from(new Uint8Array(keyBytes))
		.map(byte => byte.toString(16).padStart(2, '0'))
		.join('');

	return keyHex;
}

async function generateAndReturnIV() {
	const iv = crypto.getRandomValues(new Uint8Array(16));
	const ivString = JSON.stringify(Array.from(iv));
	return ivString;
}

// Google Drive File Download API
async function download(id, range = '', inline) {
	let url = `https://www.googleapis.com/drive/v3/files/${id}?alt=media`;
	const requestOption = await requestOptions();
	requestOption.headers['Range'] = range;
	let file = await getFileInfo(id);
	console.log(JSON.stringify(file));
	if (!file.name) {
		return error_page("File not found.");
	}
	let res;
	for (let i = 0; i < 3; i++) {
		res = await fetch(url, requestOption);
		if (res.ok) {
			break;
		}
		await sleep(800 * (i + 1));
		console.log(res);
	}
	if (res.ok) {
		const {
			headers
		} = res = new Response(res.body, res)
		headers.set("Content-Disposition", `attachment; filename="${file.name}"`);
		headers.set("Content-Length", file.size);
		authConfig.enable_cors_file_down && headers.append('Access-Control-Allow-Origin', '*');
		inline === true && headers.set('Content-Disposition', 'inline');
		return res;
	} else if (res.status == 404) {
		return error_page("File not found.");
	} else if (res.status == 403) {
		return error_page("Permission denied.");
	} else {
		return error_page("Unknown error.");
	}
}

// Google Drive File Info API
async function getFileInfo(id) {
	let url = `https://www.googleapis.com/drive/v3/files/${id}?fields=name,size,fileExtension,fullFileExtension,md5Checksum,sha1Checksum,sha256Checksum,createdTime,modifiedTime`;
	let requestOption = await requestOptions();
	let res = await fetch(url, requestOption);
	return await res.json()
}

// Google Drive Request Options
async function requestOptions(headers = {}, method = 'GET') {
	const Token = await accessToken();
	headers['authorization'] = 'Bearer ' + Token;
	return {
		'method': method,
		'headers': headers
	};
}

// Google Drive Access Token API
async function accessToken() {
	console.log("accessToken");
	if (authConfig.expires == undefined || authConfig.expires < Date.now()) {
		const obj = await fetchAccessToken();
		if (obj.access_token != undefined) {
			authConfig.accessToken = obj.access_token;
			authConfig.expires = Date.now() + 3500 * 1000;
		}
	}
	return authConfig.accessToken;
}

// Google Drive Fetch Access Token API
async function fetchAccessToken() {
	console.log("fetchAccessToken");
	const url = "https://www.googleapis.com/oauth2/v4/token";
	const headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	var post_data;
	if (authConfig.service_account && typeof authConfig.service_account_json != "undefined") {
		const jwttoken = await JSONWebToken.generateGCPToken(authConfig.service_account_json);
		post_data = {
			grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
			assertion: jwttoken,
		};
	} else {
		post_data = {
			client_id: authConfig.client_id,
			client_secret: authConfig.client_secret,
			refresh_token: authConfig.refresh_token,
			grant_type: "refresh_token",
		};
	}

	let requestOption = {
		'method': 'POST',
		'headers': headers,
		'body': enQuery(post_data)
	};

	let response;
	for (let i = 0; i < 3; i++) {
		response = await fetch(url, requestOption);
		if (response.ok) {
			break;
		}
		await sleep(800 * (i + 1));
	}
	return await response.json();
}

// Handling Encoded Query
function enQuery(data) {
	const ret = [];
	for (let d in data) {
		ret.push(encodeURIComponent(d) + '=' + encodeURIComponent(data[d]));
	}
	return ret.join('&');
}

// Sleep to Retry Function
async function sleep(ms) {
	return new Promise(function(resolve, reject) {
		let i = 0;
		setTimeout(function() {
			console.log('sleep' + ms);
			i++;
			if (i >= 2) reject(new Error('i>=2'));
			else resolve(i);
		}, ms);
	})
}

// Service Account JSON Web Token Generator
const JSONWebToken = {
	header: {
		alg: 'RS256',
		typ: 'JWT'
	},
	importKey: async function(pemKey) {
		var pemDER = this.textUtils.base64ToArrayBuffer(pemKey.split('\n').map(s => s.trim()).filter(l => l.length && !l.startsWith('---')).join(''));
		return crypto.subtle.importKey('pkcs8', pemDER, {
			name: 'RSASSA-PKCS1-v1_5',
			hash: 'SHA-256'
		}, false, ['sign']);
	},
	createSignature: async function(text, key) {
		const textBuffer = this.textUtils.stringToArrayBuffer(text);
		return crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, textBuffer)
	},
	generateGCPToken: async function(serviceAccount) {
		const iat = parseInt(Date.now() / 1000);
		var payload = {
			"iss": serviceAccount.client_email,
			"scope": "https://www.googleapis.com/auth/drive",
			"aud": "https://oauth2.googleapis.com/token",
			"exp": iat + 3600,
			"iat": iat
		};
		const encPayload = btoa(JSON.stringify(payload));
		const encHeader = btoa(JSON.stringify(this.header));
		var key = await this.importKey(serviceAccount.private_key);
		var signed = await this.createSignature(encHeader + "." + encPayload, key);
		return encHeader + "." + encPayload + "." + this.textUtils.arrayBufferToBase64(signed).replace(/\//g, '_').replace(/\+/g, '-');
	},
	textUtils: {
		base64ToArrayBuffer: function(base64) {
			var binary_string = atob(base64);
			var len = binary_string.length;
			var bytes = new Uint8Array(len);
			for (var i = 0; i < len; i++) {
				bytes[i] = binary_string.charCodeAt(i);
			}
			return bytes.buffer;
		},
		stringToArrayBuffer: function(str) {
			var len = str.length;
			var bytes = new Uint8Array(len);
			for (var i = 0; i < len; i++) {
				bytes[i] = str.charCodeAt(i);
			}
			return bytes.buffer;
		},
		arrayBufferToBase64: function(buffer) {
			let binary = '';
			let bytes = new Uint8Array(buffer);
			let len = bytes.byteLength;
			for (let i = 0; i < len; i++) {
				binary += String.fromCharCode(bytes[i]);
			}
			return btoa(binary);
		}
	}
};

const html = `
<html>
<head>
<title>Download API</title>
<style>
body{
    margin:0;
    padding:0;
    width:100%;
    height:100%;
    color:#b0bec5;
    display:table;
    font-weight:100;
    font-family:Lato
}
.container{
    text-align:center;
    display:table-cell;
    vertical-align:middle
}
.content{
    text-align:center;
    display:inline-block
}
.message{
    font-size:80px;
    margin-bottom:40px
}
.submessage{
    font-size:40px;
    margin-bottom:40px
}
.copyright{
    font-size:20px;
}
a{
    text-decoration:none;
    color:#3498db
}

</style>
</head>
<body>
<div class="container">
<div class="content">
<div class="message">Download API</div>
<div class="submessage">All Systems Operational</div>
<div class="copyright">Planet Earth</div>
</div>
</div>
</body>
</html>
`;