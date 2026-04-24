from flask import Flask, request, jsonify
import subprocess, os

app = Flask(__name__)

# Simulated IoT device state
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

# Intentionally vulnerable endpoint — command injection
@app.route('/ping')
def ping():
    host = request.args.get('host', 'localhost')
    # VULNERABLE: no sanitization on purpose
    result = subprocess.getoutput(f"ping -c 1 {host}")
    return jsonify({"result": result})

# Intentionally vulnerable — exposes device config
@app.route('/config')
def config():
    return jsonify({
        "admin_password": "admin123",
        "mqtt_broker": "localhost",
        "mqtt_topic": "iot/sensors",
        "api_key": "iot-secret-key-001"
    })

@app.route('/update', methods=['POST'])
def update():
    data = request.json or {}
    device.update(data)
    return jsonify({"updated": True, "device": device})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
