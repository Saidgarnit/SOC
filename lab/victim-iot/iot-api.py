from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

device = {
    "id": "iot-device-001",
    "type": "smart-sensor",
    "temperature": 22.5,
    "humidity": 60,
    "status": "online",
    "firmware": "1.0.0"
}

@app.route('/')
def index():
    return jsonify({"device": device, "api": "IoT Simulator v1.0"})

@app.route('/status')
def status():
    return jsonify(device)

@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    result = subprocess.getoutput(f"ping -c 1 {host}")
    return jsonify({"result": result})

@app.route('/config')
def config():
    return jsonify({
        "admin_password": "admin123",
        "mqtt_broker": "localhost",
        "api_key": "iot-secret-key-001"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
