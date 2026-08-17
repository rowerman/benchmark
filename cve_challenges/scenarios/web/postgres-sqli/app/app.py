import os
import psycopg2
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'db'),
    'user': os.environ.get('DB_USER', 'products'),
    'password': os.environ.get('DB_PASS', 'productspass'),
    'dbname': os.environ.get('DB_NAME', 'shop'),
}


@app.route('/')
def index():
    return '<h1>Product Search</h1><form action="/search"><input name="q" placeholder="Search products..."></form>'


@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.set_client_encoding('BIG5')
        cur = conn.cursor()
        # Vulnerable: direct string concatenation into SQL query
        query = f"SELECT name, price FROM products WHERE name LIKE '%{keyword}%'"
        cur.execute(query)
        results = cur.fetchall()
        return jsonify([{'name': r[0], 'price': str(r[1])} for r in results])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
