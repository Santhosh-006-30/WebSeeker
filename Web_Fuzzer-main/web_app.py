
from flask import Flask, render_template, request, jsonify, Response, send_file
import threading
import queue
import time
import json
import os
from core.engine import ScannerEngine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')

app = Flask(__name__, template_folder=TEMPLATES_DIR)


# Global state
scan_state = {
    "is_running": False,
    "progress": 0,
    "result": None,
    "active_engine": None,
    "start_time": None,
    "endpoint_count": 0
}
# Using a list of queues for multiple potential listeners (browser tabs)
listeners = []

def broadcast_message(data):
    for q in listeners[:]:
        try:
            q.put(data)
        except queue.Full:
            listeners.remove(q)

def scan_worker(url):
    global scan_state
    scan_state["is_running"] = True
    scan_state["progress"] = 0
    scan_state["result"] = None
    scan_state["start_time"] = time.time()

    def callback(type, message):
        timestamp = time.strftime("%H:%M:%S")
        
        # Color codes for terminal
        colors = {
            'info': '\033[94m',    # Blue
            'success': '\033[92m', # Green
            'warning': '\033[93m', # Yellow
            'error': '\033[91m',   # Red
            'reset': '\033[0m'
        }
        
        if type == 'progress':
            try:
                prog_val = int(message)
                scan_state["progress"] = prog_val
                broadcast_message(f"data: {json.dumps({'type': 'progress', 'value': prog_val})}\n\n")
            except:
                pass
        elif type == 'eta':
             broadcast_message(f"data: {json.dumps({'type': 'eta', 'value': message})}\n\n")
        else:
            # Info/Error/Success
            color = colors.get(type, colors['reset'])
            # Print to terminal
            print(f"{color}[{timestamp}] [{type.upper()}] {message}{colors['reset']}")
            
            data = {
                'type': 'log',
                'level': type,
                'message': f"[{timestamp}] {message}"
            }
            broadcast_message(f"data: {json.dumps(data)}\n\n")

    try:
        print(f"\nStarting scan for {url}...\n")
        engine = ScannerEngine(output_callback=callback)
        scan_state["active_engine"] = engine
        results = engine.run_scan(url)
        scan_state["result"] = results
        # Send completion event — include vulnerability list for findings dashboard
        payload = dict(results) if results else {}
        broadcast_message(f"data: {json.dumps({'type': 'complete', 'results': payload})}\n\n")
        print("\nScan complete.\n")
    except Exception as e:
        broadcast_message(f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n")
    finally:
        scan_state["is_running"] = False
        scan_state["active_engine"] = None
        scan_state["progress"] = 100
        broadcast_message(f"data: {json.dumps({'type': 'progress', 'value': 100})}\n\n")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    if scan_state["is_running"]:
        return jsonify({"status": "error", "message": "Scan is already in progress."})
    
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"status": "error", "message": "URL is required."})

    thread = threading.Thread(target=scan_worker, args=(url,))
    thread.daemon = True
    thread.start()
    return jsonify({"status": "success"})

@app.route('/stop', methods=['POST'])
def stop_scan():
    if scan_state["is_running"] and scan_state["active_engine"]:
        scan_state["active_engine"].stop()
        return jsonify({"status": "success", "message": "Stopping scan..."})
    return jsonify({"status": "error", "message": "No scan running."})

@app.route('/status')
def status():
    elapsed = 0
    if scan_state["start_time"]:
        elapsed = int(time.time() - scan_state["start_time"])
    return jsonify({
        "is_running": scan_state["is_running"],
        "progress": scan_state["progress"],
        "elapsed_seconds": elapsed,
        "has_result": scan_state["result"] is not None
    })

@app.route('/stream')
def stream():
    def event_stream():
        q = queue.Queue(maxsize=100)
        listeners.append(q)
        try:
            while True:
                try:
                    msg = q.get(timeout=20)
                    yield msg
                except queue.Empty:
                    yield ": keep-alive\n\n"
        except GeneratorExit:
            listeners.remove(q)

    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/reports/<path:filename>')
def download_report(filename):
    # Ideally should be in a reports folder, but currently main.py saves to root mostly
    # We should allow serving the generated html
    return send_file(filename)

if __name__ == '__main__':
    import webbrowser
    import signal
    import sys
    
    def signal_handler(sig, frame):
        print("\nStopping Web UI...")
        # If a scan is running, try to stop it
        if scan_state["active_engine"]:
            scan_state["active_engine"].stop()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)

    print("Starting WebSeeker UI at http://localhost:5000")
    # Auto-open the dashboard
    webbrowser.open("http://localhost:5000")
    # Disable debug mode to prevent the reloader from restarting the script (which opens browser twice)
    app.run(debug=False, host='0.0.0.0', port=5000)
