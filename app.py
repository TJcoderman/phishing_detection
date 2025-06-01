from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import joblib
import sqlite3
from datetime import datetime
import os
import json
from feature_extraction import extract_features, get_url_risk_factors
from model_training import retrain_model_with_feedback, init_db

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Ensure database exists
if not os.path.exists('phishing_history.db'):
    init_db()

# Load model
try:
    model = joblib.load("model.pkl")
except FileNotFoundError:
    from model_training import train_model
    model = train_model()

@app.route("/", methods=["GET", "POST"])
def index():
    recent_checks = None
    error = None
    
    # Get recent checks for display
    try:
        conn = sqlite3.connect('phishing_history.db')
        cursor = conn.cursor()
        cursor.execute("""
            SELECT url, prediction, confidence, check_date 
            FROM url_checks 
            ORDER BY check_date DESC LIMIT 5
        """)
        recent_checks = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"Error fetching recent checks: {e}")
    
    if request.method == "POST":
        url = request.form["url"]
        
        # Basic validation
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            # Extract features
            features = extract_features(url)
            
            # Get prediction and probability
            prediction = model.predict([features])[0]
            probability = model.predict_proba([features])[0]
            
            result = "Phishing" if prediction == 1 else "Legitimate"
            confidence = probability[1] if prediction == 1 else probability[0]
            confidence_percent = round(confidence * 100, 2)
            
            # Get risk factors
            risk_factors = get_url_risk_factors(url)
            
            # Store in session for feedback
            session['last_check'] = {
                'url': url,
                'prediction': result,
                'confidence': confidence
            }
            
            # Save to database
            conn = sqlite3.connect('phishing_history.db')
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO url_checks (url, prediction, confidence, check_date) 
                VALUES (?, ?, ?, ?)
            """, (url, result, confidence, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
            
            return render_template(
                "index.html", 
                result=result, 
                url=url,
                confidence=confidence_percent,
                risk_factors=risk_factors,
                recent_checks=recent_checks
            )
        except Exception as e:
            error = f"Error analyzing URL: {str(e)}"
            return render_template("index.html", error=error, recent_checks=recent_checks)
            
    return render_template("index.html", result=None, recent_checks=recent_checks)

@app.route("/report", methods=["POST"])
def report():
    if 'last_check' not in session:
        return redirect(url_for('index'))
    
    url = session['last_check']['url']
    prediction = session['last_check']['prediction']
    feedback = request.form["feedback"]
    
    # Save feedback to database
    conn = sqlite3.connect('phishing_history.db')
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE url_checks 
        SET user_feedback = ? 
        WHERE url = ? AND prediction = ? 
        ORDER BY check_date DESC LIMIT 1
    """, (feedback, url, prediction))
    conn.commit()
    conn.close()
    
    # Flash a thank you message
    session['feedback_submitted'] = True
    
    return redirect(url_for('index'))

@app.route("/history")
def history():
    # Get all URL check history
    conn = sqlite3.connect('phishing_history.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT url, prediction, confidence, check_date, user_feedback 
        FROM url_checks 
        ORDER BY check_date DESC
    """)
    history = cursor.fetchall()
    conn.close()
    
    return render_template("history.html", history=history)

@app.route("/retrain", methods=["POST"])
def retrain():
    success = retrain_model_with_feedback()
    
    if success:
        # Reload the model
        global model
        model = joblib.load("model.pkl")
        message = "Model successfully retrained with user feedback."
    else:
        message = "No new feedback available for retraining or retraining failed."
    
    return jsonify({"success": success, "message": message})

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()
    
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
    
    url = data['url']
    
    # Basic validation
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Extract features
        features = extract_features(url)
        
        # Get prediction and probability
        prediction = model.predict([features])[0]
        probability = model.predict_proba([features])[0]
        
        result = "Phishing" if prediction == 1 else "Legitimate"
        confidence = probability[1] if prediction == 1 else probability[0]
        
        # Get risk factors
        risk_factors = get_url_risk_factors(url)
        
        # Save to database
        conn = sqlite3.connect('phishing_history.db')
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO url_checks (url, prediction, confidence, check_date) 
            VALUES (?, ?, ?, ?)
        """, (url, result, confidence, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
        
        return jsonify({
            "url": url,
            "result": result,
            "confidence": round(confidence * 100, 2),
            "risk_factors": risk_factors
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)