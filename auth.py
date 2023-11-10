from flask import Flask, request
import jwt
import datetime
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", default="somesecretkey")

@app.route('/get_token', methods=['GET'])
def get_token():
    email = request.args.get('email', None)
    if not email:
        return {'message': 'Email is missing'}, 400

    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=3),
            'iat': datetime.datetime.utcnow(),
            'sub': email
        }
        token = jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
        return {
            'token': token
        }, 200
    except Exception as e:
        print(e)
        return {
            'message': 'Token generation failed'
        }, 500

@app.route('/verify_token', methods=['POST'])
def verify_token():
    token = request.json.get('token', None)
    if not token:
        return {'message': 'Token is missing'}, 400
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms='HS256')
        return {'email': data['sub']}, 200
    except Exception as ex:
        print(ex)
        return {'message': 'Token is invalid'}, 403

if __name__ == '__main__':
    app.run(debug=True, port=5001, host="0.0.0.0")