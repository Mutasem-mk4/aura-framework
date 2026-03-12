from flask import Flask, request, jsonify

app = Flask(__name__)

# Mock database
users = {
    1: {"name": "Admin", "balance": 999999, "secret": "super_secret_admin_key"},
    2: {"name": "User", "balance": 100, "secret": "user_key_123"}
}

@app.route('/api/profile', methods=['GET'])
def get_profile():
    # Vulnerable to IDOR: NO authorization check
    user_id = request.args.get('id')
    if not user_id:
        return jsonify({"error": "Missing id parameter"}), 400
        
    try:
        user_id = int(user_id)
        if user_id in users:
            return jsonify(users[user_id]), 200
        else:
            return jsonify({"error": "User not found"}), 404
    except ValueError:
        return jsonify({"error": "Invalid id format"}), 400

@app.route('/api/transfer', methods=['GET'])
def transfer_funds():
    # Vulnerable to Logic Flaw: No check for negative amount
    amount = request.args.get('amount')
    if not amount:
        return jsonify({"error": "Missing amount parameter"}), 400
        
    try:
        amount = float(amount)
        # INSECURE LOGIC: We accept negative numbers!
        users[2]["balance"] -= amount
        return jsonify({"success": True, "new_balance": users[2]["balance"]}), 200
    except ValueError:
        return jsonify({"error": "Invalid amount format"}), 400

if __name__ == '__main__':
    app.run(port=5000)
