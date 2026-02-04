# Vulnerable Pug/Express SSTI Test Environment
# WARNING: This container is intentionally vulnerable - DO NOT use in production!

FROM node:20-slim

WORKDIR /app

# Initialize package.json and install dependencies
RUN npm init -y && npm install express pug

# Create vulnerable Express application inline
RUN cat > app.js << 'EOF'
const express = require('express');
const pug = require('pug');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/', (req, res) => {
    res.send(`
    <h1>Vulnerable Pug SSTI Test</h1>
    <p>This application is intentionally vulnerable to Server-Side Template Injection.</p>
    <h2>Test Endpoints:</h2>
    <ul>
        <li>GET /greet?name=YOUR_PAYLOAD - Vulnerable to SSTI via query parameter</li>
        <li>POST /render - Vulnerable to SSTI via form body (param: template)</li>
    </ul>
    <h2>Example payloads:</h2>
    <code>#{7*7}</code> should return <code>49</code><br>
    <code>#{7*191}</code> should return <code>1337</code>
    `);
});

app.get('/greet', (req, res) => {
    // VULNERABLE: User input directly compiled as Pug template
    const name = req.query.name || 'World';
    try {
        const template = pug.compile('p Hello, ' + name + '!');
        res.send(template());
    } catch (err) {
        res.status(500).send('Template Error: ' + err.message);
    }
});

app.post('/render', (req, res) => {
    // VULNERABLE: User-controlled template
    const template = req.body.template || '';
    try {
        const compiled = pug.compile(template);
        res.send(compiled());
    } catch (err) {
        res.status(500).send('Template Error: ' + err.message);
    }
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Vulnerable Pug server running on http://0.0.0.0:${PORT}`);
});
EOF

EXPOSE 3000

CMD ["node", "app.js"]
