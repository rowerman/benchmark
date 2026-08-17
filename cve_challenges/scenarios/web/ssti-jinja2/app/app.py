from flask import Flask, request, render_template
from jinja2 import Template

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/submit', methods=['POST'])
def submit():
    name = request.form.get('name', '')

    # VULNERABILITY: User input passed directly to jinja2.Template()
    # This allows Server-Side Template Injection (SSTI)
    template = Template(f'Thank you {name} for your submission.')
    rendered = template.render()

    return render_template('result.html', message=rendered)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
