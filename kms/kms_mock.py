from flask import Flask, request, jsonify
import secrets
import base64

app = Flask(__name__)
keys = {}

@app.route('/', methods=['POST'])
def key_management():
  data = request.get_json()
  print(data)

  # sanitize
  if not data or 'path' not in data:
    return jsonify({"error": "Invalid input. Expected JSON with 'path'."}), 400

  path = data['path']
  keylen = 32

  if path not in keys:
    keys[path] = secrets.token_bytes(keylen)

  # base64 encode for resp
  b64_key = base64.b64encode(keys[path]).decode('utf-8')
  print("DEBUG:", path, b64_key)
  return jsonify({"key": b64_key})

if __name__ == '__main__':
    app.run(debug=True)
