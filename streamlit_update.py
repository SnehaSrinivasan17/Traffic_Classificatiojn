import streamlit as st
import pandas as pd
import pickle
from sklearn.preprocessing import MinMaxScaler, Normalizer
import io
import hashlib

def hash_path(path):
    return int(hashlib.sha1(path.encode('utf-8')).hexdigest(), 16) % (10 ** 8)

with open(r"C:\Users\sneha\Downloads\old_nw\xgb_model_1.pkl", 'rb') as file:
    xgb_model = pickle.load(file)

with open(r"C:\Users\sneha\Downloads\random_forest_model.pkl", 'rb') as file:
    random_forest_model = pickle.load(file)

def classify_traffic(instance):
    if len(instance.columns) == 70:
        columns = ['Tot Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max',
                    'Flow Pkts/s', 'Flow IAT Max', 'Fwd Pkts/s', 'Bwd Pkts/s',
                    'Pkt Len Max', 'Pkt Len Std', 'Fwd Seg Size Avg', 'Subflow Bwd Pkts',
                    'Init Fwd Win Byts', 'Fwd Seg Size Min']
        
        X = instance[columns]
        # min_max_scaler = MinMaxScaler()
        # X_normalized = pd.DataFrame(min_max_scaler.fit_transform(X), columns=columns)
        xgb_predictions = xgb_model.predict(X)

        class_labels_xgb = {
            0: 'Normal or Benign Traffic',
            1: 'Malicious Traffic: Brute Force - Web',
            2: 'Malicious Traffic: Brute Force - XSS',
            3: 'Malicious Traffic: FTP-BruteForce',
            4: 'Malicious Traffic: Infilteration',
            5: 'Malicious Traffic: SQL Injection',
            6: 'Malicious Traffic: SSH-Bruteforce'
        }

        st.markdown(f'<b><div class="display">XGBoost Predicted labels</div></b>', unsafe_allow_html=True)
        
        for i, prediction_result in enumerate(xgb_predictions):
            if prediction_result in class_labels_xgb:
                predicted_label = class_labels_xgb[prediction_result]
                if predicted_label == 'Normal or Benign Traffic':
                    st.markdown(f'<div class="output-label-green">Instance {i} - {predicted_label}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="output-label-red">Instance {i} - {predicted_label}</div>', unsafe_allow_html=True)
            else:
                st.write(f"Instance {i}: Class not recognized")
       
    elif len(instance.columns) == 6:  
        columns = ['process_id', 'system_call', 'event_id', 'path']

        instance['path'] = instance['path'].apply(hash_path)

        unit_vector_scaler = Normalizer(norm='l2')
        instance_normalized = unit_vector_scaler.transform(instance[columns])
        rf_predictions = random_forest_model.predict(instance_normalized)

        class_labels_rf = {
            0: "Normal or Benign Traffic",
            1: "Malicious Traffic (Exploits)",
            2: "Malicious Traffic (Backdoors)",
            3: "Malicious Traffic (Shellcode)",
            4: "Malicious Traffic (Worms)"
        }

        st.markdown(f'<b><div class="display">Random Forest Predicted labels</div></b>', unsafe_allow_html=True)
    
        for i, prediction_result in enumerate(rf_predictions):
            if prediction_result in class_labels_rf:
                predicted_label = class_labels_rf[prediction_result]
                if predicted_label == 'Normal or Benign Traffic':
                    st.markdown(f'<div class="output-label-green">{predicted_label}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="output-label-red">{predicted_label}</div>', unsafe_allow_html=True)
            else:
                st.write(f"Instance {i + 1}: Class not recognized")

    else:
        st.error("Invalid number of columns in the instance.")

def main():
    custom_styles = """
        <style>
            body {
                font-family: 'Helvetica', sans-serif;
                background-color: #290000;
            }
            .title {
                color: #F7B538;
                text-align: center;
                font-size: 60px;
                margin-bottom: 40px;
                margin-left:20px;
            }
            .paragraph {
                color: #FFDAB9;
                text-align: center;
                font-size: 30px;
                margin-bottom: 70px;
            }
            .display {
                color: #FFDAB9;
                text-align: center;
                font-size: 25px;
                margin-top: 50px;
                margin-bottom: 20px;
            }
            .upload {
                color: #FFDAB9;
                font-size: 20px;
                margin-up: 170px;
            }
            .data{
                color: #FFFFFF;
                font-size: 20px;
            }
            .output-label-green {
                background-color: #3d0000;  
                color: #4CAF50;
                padding: 10px;
                margin: 5px;
                margin-left: 20px
            }
            .output-label-red {
                background-color: #3d0000;  
                color: #FF5733;
                padding: 10px;
                margin: 5px;
                margin-left: 20px
            }

        </style>
    """
    st.markdown(custom_styles, unsafe_allow_html=True)

    st.markdown('<div class="title">Welcome to Bakshi!</div>', unsafe_allow_html=True)
    st.markdown('<div class="paragraph">Bakshi is an application for classifying network or malware traffic.</div>', unsafe_allow_html=True)

    st.markdown('<div class="data">Please upload a CSV file of the instances.</div>', unsafe_allow_html=True)
    uploaded_file = st.file_uploader(" ",type=["csv"])

    if uploaded_file is not None:
        st.success("File uploaded successfully!")

        instance = pd.read_csv(io.BytesIO(uploaded_file.read()))

        st.markdown(f'<b><div class="display">Uploaded Data</div></b>', unsafe_allow_html=True)
        st.dataframe(instance, width=800, height=400)

        classify_traffic(instance)

if __name__ == "__main__":
    main()
