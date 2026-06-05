from flask import Flask, request, jsonify, render_template_string
import pymongo
import os

app = Flask(__name__)

# Connect to MongoDB (hostname from environment or default to 'mongo')
mongo_host = os.environ.get('MONGO_HOST', 'mongo')
mongo_client = pymongo.MongoClient(f'mongodb://{mongo_host}:27017/')
db = mongo_client['test']

LOGIN_FORM = '''
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h2>Login</h2>
  <form method="post" action="/login">
    <label>Username: <input type="text" name="username"></label><br>
    <label>Password: <input type="password" name="password"></label><br>
    <input type="submit" value="Login">
  </form>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(LOGIN_FORM)

@app.route('/login', methods=['POST'])
def login():
    # Accept both JSON and form-encoded data
    if request.is_json:
        data = request.get_json()
    else:
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        data = {'username': username, 'password': password}

    # VULNERABILITY: User input passed directly to MongoDB query
    # This allows NoSQL injection via operators like $ne, $gt, $regex
    user = db.users.find_one({"username": data['username'], "password": data['password']})

    if user:
        return jsonify({
            'message': 'Login successful!',
            'user': user.get('username'),
            'role': user.get('role'),
            'flag': user.get('flag', 'No flag for you')
        })
    else:
        return jsonify({'message': 'Login failed'}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
