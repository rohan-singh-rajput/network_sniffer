from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import json
import os

app = Flask(__name__)
CORS(app)


@app.route("/packets")
def get_packets():
    try:
        with open("packets.json") as f:
            lines = f.readlines()
            json_lines = [json.loads(line) for line in lines[-100:]]  # last 100 packets
        return jsonify(json_lines)
    except Exception as e:
        return jsonify([])


@app.route("/getstats")
def serve_stats_page():
    return send_from_directory(".", "stats.html")


@app.route("/stats")
def get_stats():
    try:
        with open("packets.json") as f:
            lines = f.readlines()
        stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
        for line in lines[-200:]:  # last 200 packets
            pkt = json.loads(line)
            proto = pkt.get("protocol", "OTHER")
            if proto in stats:
                stats[proto] += 1
            else:
                stats["OTHER"] += 1
        return jsonify(stats)
    except:
        return jsonify({"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0})


@app.route("/")
def root():
    return send_from_directory(".", "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory(".", path)


if __name__ == "__main__":
    app.run(debug=True)
