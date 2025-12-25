from flask import Flask, request, jsonify
import sqlite3, os

app = Flask(__name__)
DB = "malware.db"

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    file_hash = data.get("hash")

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT malware_name, threat_level FROM malware_signatures WHERE file_hash=?",(file_hash,))
    row = cur.fetchone()
    conn.close()

    if row:
        return jsonify({"status":"MALICIOUS","name":row[0],"level":row[1]})
    else:
        return jsonify({"status":"SAFE"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)