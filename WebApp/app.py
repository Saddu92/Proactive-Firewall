from flask import Flask, render_template, request
import pandas as pd
import xgboost as xgb
import joblib

# Initialize Flask app
app = Flask(__name__)

# Load the trained model
model = joblib.load('model/xgboost_model.pkl')  # Path to your trained model

# Function to predict the packet type (Benign or Malicious)
from flask import render_template
import pandas as pd

def predict_packet_type(user_data):
    # Predict the packet types (returns an array of predictions)
    predictions = model.predict(user_data)
    
    # Create a DataFrame to show results
    packet_results = pd.DataFrame(user_data)  # Create DataFrame from the user data (packets)
    packet_results['Prediction'] = predictions  # Add the prediction results
    
    # Map the numerical predictions (1/0) to 'Malicious' and 'Benign'
    packet_results['Label'] = packet_results['Prediction'].map({1: 'Malicious', 0: 'Benign'})
    
    return packet_results  # Return DataFrame with packet data and predictions


@app.route('/')
def home():
    return render_template('index.html')  # A simple HTML form to upload CSV

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        # Get the uploaded CSV file from the form
        file = request.files['file']
        
        if file:
            # Read the CSV file into a DataFrame
            user_data = pd.read_csv(file)
            
            # Preprocess the file if needed (e.g., scaling, handling missing values)
            # Assuming preprocessing is already done here
            
            # Get prediction results
            packet_results = predict_packet_type(user_data)
            
            # Convert the DataFrame to an HTML table
            packet_results_html = packet_results.to_html(classes='table table-striped', index=False)
            
            # Display the result in a new template
            return render_template('result.html', table=packet_results_html)


if __name__ == '__main__':
    app.run(debug=True)
