# Vulnerable Jinja2/Flask SSTI Test Environment
# WARNING: This container is intentionally vulnerable - DO NOT use in production!

FROM python:3.11-slim

WORKDIR /app

# Install Flask
RUN pip install --no-cache-dir flask

# Create vulnerable Flask application inline
RUN cat > app.py << 'EOF'
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>Vulnerable Jinja2 SSTI Test</h1>
    <p>This application is intentionally vulnerable to Server-Side Template Injection.</p>
    <h2>Test Endpoints:</h2>
    <ul>
        <li>GET /greet?name=YOUR_PAYLOAD - Vulnerable to SSTI via query parameter</li>
        <li>POST /render - Vulnerable to SSTI via form body (param: template)</li>
    </ul>
    <h2>Example payloads:</h2>
    <code>{{7*7}}</code> should return <code>49</code><br>
    <code>{{7*191}}</code> should return <code>1337</code>
    '''

@app.route('/greet')
def greet():
    # VULNERABLE: User input directly in template
    name = request.args.get('name', 'World')
    template = f'Hello, {name}!'
    return render_template_string(template)

@app.route('/render', methods=['POST'])
def render():
    # VULNERABLE: User-controlled template
    template = request.form.get('template', '')
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
EOF

EXPOSE 5000

CMD ["python", "app.py"]
