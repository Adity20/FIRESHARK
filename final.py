import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
import pickle
import time
from datetime import datetime
import requests
import csv
import os
from dotenv import load_dotenv
load_dotenv()
import imaplib
import email
from email.parser import BytesParser, Parser
from email.policy import default
import os
import re
import requests
from bs4 import BeautifulSoup
import numpy as np
import socket
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import streamlit as st
from transformers import pipeline


st.set_page_config(page_title="Network Flow IDS", layout="wide", page_icon=":shield:")

def load_data():
    df = pd.read_csv('./data/network_traffic.csv')
    return df

def preprocess_data(df):
    df_processed = df.copy()
    df_processed['Label'] = df_processed['Label'].apply(lambda x: 1 if x != 'BENIGN' else 0)
    return df_processed

def train_model(X_train, y_train):
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    return clf

def create_feature_importance_plot(model, feature_names):
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    fig = go.Figure(data=[go.Bar(
        x=[feature_names[i] for i in indices],
        y=[importances[i] for i in indices],
        text=[f"{importances[i]:.3f}" for i in indices],
        textposition='auto',
    )])
    
    fig.update_layout(
        title='Feature Importance',
        xaxis_title='Features',
        yaxis_title='Importance Score',
        xaxis_tickangle=-45
    )
    
    return fig

def analyze_logs(log_data):
    log_lines = log_data.split('\n')
    error_count = sum(1 for line in log_lines if 'ERROR' in line)
    warning_count = sum(1 for line in log_lines if 'WARNING' in line)

    st.write(f"Total log entries: {len(log_lines)}")
    st.write(f"Error entries: {error_count}")
    st.write(f"Warning entries: {warning_count}")
    
    st.subheader("Sample Log Entries")
    st.text("\n".join(log_lines[:10]))

# Function to generate an attack report (with a DataFrame containing a 'Label' column)
def generate_attack_report(df):
    if 'Label' not in df.columns:
        st.write("Dataframe must contain a 'Label' column for attack types.")
        return
    
    attack_counts = df['Label'].value_counts()
    attack_summary = attack_counts[attack_counts.index != 'BENIGN']

    st.write("### Attack Summary")
    st.write(attack_summary)

    fig = px.bar(attack_summary, x=attack_summary.index, y=attack_summary.values, 
                 labels={'x': 'Attack Type', 'y': 'Count'}, title="Attack Distribution")
    st.plotly_chart(fig)
    


API_KEY = os.getenv("API_KEY")
def lookup_input(input_value):
    """
    Lookup an IP Address or Subnet using the AbuseIPDB API.
    For domains, resolve them to an IP address first.
    """
    api_url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": API_KEY
    }
    
    params = {
        "maxAgeInDays": 90  # Look back for up to 90 days of abuse reports
    }
    
    try:
        if "/" in input_value:  # Check if it's a subnet
            params["ipAddress"] = input_value
        elif "." in input_value and not input_value.replace(".", "").isdigit():  # Domain name
            resolved_ip = socket.gethostbyname(input_value)
            params["ipAddress"] = resolved_ip
        else:  # Assume it's an IP address
            params["ipAddress"] = input_value

        response = requests.get(api_url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "Input": input_value,
                "Resolved IP": params.get("ipAddress"),
                "Is Malicious": data.get("isPublic", False),
                "Threat Score": data.get("abuseConfidenceScore", 0),
                "Last Reported": data.get("lastReportedAt", "Unknown"),
                "Category": data.get("usageType", "N/A"),
                "ISP": data.get("isp", "Unknown"),
                "Country": data.get("countryName", "Unknown")
            }
        else:
            return {"error": f"API request failed with status code {response.status_code}: {response.text}"}
    except socket.gaierror:
        return {"error": "Failed to resolve domain to an IP address."}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}

def display_threat_intelligence():
    """
    Display threat intelligence information in the Streamlit UI.
    """
    st.title("Threat Intelligence Lookup")
    st.markdown("Check an IP Address, Domain Name, or Subnet for potential malicious activity.")
    
    user_input = st.text_input("Enter an IP Address, Domain Name, or Subnet (e.g., 192.168.1.1, example.com, 192.168.0.0/24):")

    if user_input:
        with st.spinner("Looking up threat intelligence data..."):
            result = lookup_input(user_input)
        
        if "error" in result:
            st.error(result["error"])
        else:
            st.write("### Threat Intelligence Results")
            st.write(f"**Input**: {result['Input']}")
            st.write(f"**Resolved IP**: {result['Resolved IP']}")
            st.write(f"**Is Malicious**: {'Yes' if result['Is Malicious'] else 'No'}")
            st.write(f"**Threat Score**: {result['Threat Score']}")
            st.write(f"**Last Reported**: {result['Last Reported']}")
            st.write(f"**Category**: {result['Category']}")
            st.write(f"**ISP**: {result['ISP']}")
            st.write(f"**Country**: {result['Country']}")
            
            if result['Is Malicious']:
                st.warning("This input has a history of malicious activity.")
            else:
                st.success("This input appears to be safe.")
                
def save_flow_data(flow_data, predictions, filename):
    """
    Save flow data along with predictions to a CSV file.
    
    Args:
        flow_data (pd.DataFrame): Original flow data
        predictions (dict): Dictionary containing prediction results
        filename (str): Name of the CSV file to save
    """
    save_df = flow_data.copy()
    
    save_df['detection_time'] = predictions['detection_time']
    save_df['predicted_label'] = predictions['prediction']
    save_df['prediction_confidence'] = predictions['confidence']
   
    os.makedirs('captured_data', exist_ok=True)
    
   
    filepath = os.path.join('captured_data', filename)
    
   
    if os.path.exists(filepath):
        save_df.to_csv(filepath, mode='a', header=False, index=False)
    else:
        save_df.to_csv(filepath, index=False)
    
    return filepath

def live_detection():
    st.header("Live Flow Analysis")
    
    try:
        with open('ids_model.pkl', 'rb') as f:
            model = pickle.load(f)
        with open('ids_scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)

        st.sidebar.subheader("Data Capture Settings")
        save_data = st.sidebar.checkbox("Save flow data", value=True)
        custom_filename = st.sidebar.text_input(
            "Custom filename (optional)", 
            value=f"flow_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if st.button("Start Flow Monitoring"):
            placeholder = st.empty()
            metrics_placeholder = st.empty()
            chart_placeholder = st.empty()
            
            flow_history = []
            saved_flows_count = 0
            
            for i in range(50):
                df = load_data()
                random_flow = df.iloc[np.random.randint(len(df))].copy()
                scaled_flow = scaler.transform(random_flow.drop('Label').values.reshape(1, -1))
                prediction = model.predict(scaled_flow)[0]
                prediction_prob = model.predict_proba(scaled_flow)[0]
                
                prediction_info = {
                    'detection_time': datetime.now(),
                    'prediction': prediction,
                    'confidence': prediction_prob.max()
                }
                
                if save_data:
                    filepath = save_flow_data(
                        random_flow.to_frame().T,
                        prediction_info,
                        custom_filename
                    )
                    saved_flows_count += 1
                
                flow_history.append({
                    'time': i,
                    'prediction': prediction,
                    'confidence': prediction_prob.max()
                })
                
                with placeholder.container():
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Flow ID", f"#{i+1}")
                    with col2:
                        if prediction == 0:
                            st.success("Benign Flow")
                        else:
                            st.error("Suspicious Flow")
                    with col3:
                        st.metric("Confidence", f"{prediction_prob.max():.2%}")
                    
                    # Add saved flows counter if saving is enabled
                    if save_data:
                        st.info(f"Saved flows: {saved_flows_count}")
                        st.text(f"Saving to: {filepath}")
                    
                    st.json({
                        'Flow Duration': f"{random_flow['Flow Duration']:.2f}",
                        'Fwd Packets': f"{random_flow['Total Fwd Packets']:.2f}",
                        'Bwd Packets': f"{random_flow['Total Backward Packets']:.2f}",
                        'Fwd Bytes': f"{random_flow['Total Length of Fwd Packets']:.2f}",
                        'Bwd Bytes': f"{random_flow['Total Length of Bwd Packets']:.2f}"
                    })
                
                if len(flow_history) > 1:
                    history_df = pd.DataFrame(flow_history)
                    fig = px.line(history_df, x='time', y='confidence',
                                color=history_df['prediction'].astype(str),
                                title='Flow Analysis History',
                                color_discrete_map={'0': 'green', '1': 'red'})
                    chart_placeholder.plotly_chart(fig)
                
                time.sleep(0.5)
            
            if save_data:
                st.success(f"""
                Flow monitoring completed!
                - Total flows captured: {saved_flows_count}
                - Data saved to: {filepath}
                """)
                
    except FileNotFoundError:
        st.error("Please train the model first!")    

def save_feedback_to_csv(feedback):
    """
    Save the user feedback to a CSV file.
    """
    file_path = "feedback.csv"
    file_exists = os.path.isfile(file_path)
    with open(file_path, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Feedback"])
        
        writer.writerow([feedback])       




def connect_to_email(host, username, password):
    """Connect to an IMAP email server."""
    mail = imaplib.IMAP4_SSL(host)
    mail.login(username, password)
    return mail

def fetch_emails(mail, folder='inbox'):
    """Fetch emails from a specified folder."""
    mail.select(folder)
    _, data = mail.search(None, 'ALL')
    for num in data[0].split():
        _, data = mail.fetch(num, '(RFC822)')
        yield email.message_from_bytes(data[0][1], policy=default)

def extract_email_features(msg):
    """Extract features from an email message."""
    subject = msg['Subject']
    from_addr = msg['From']
    body = get_email_body(msg)
    attachments = get_email_attachments(msg)
    links = extract_links(body)
    return subject, from_addr, body, attachments, links

def get_email_body(msg):
    """Get the plain text body of an email message."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                return part.get_payload(decode=True).decode('utf-8')
    else:
        return msg.get_payload(decode=True).decode('utf-8')

def get_email_attachments(msg):
    """Extract attachments from an email message."""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                attachments.append(part)
    return attachments

def extract_links(text):
    """Extract links from the email body."""
    link_pattern = r'https?://\S+|www\.\S+'
    return re.findall(link_pattern, text)

def analyze_attachments(attachments):
    """Analyze the attachments for potential malware."""
    attachment_scores = []
    for attachment in attachments:
        filename = attachment.get_filename()
        if filename:
            score = analyze_file(filename, attachment.get_payload(decode=True))
            attachment_scores.append((filename, score))
    return attachment_scores

# def analyze_file(filename, content):
#     """Analyze a file for potential malware."""
#     # Implement file analysis logic here (e.g., using VirusTotal API)
#     # Return a malware score between 0 and 1 (0 = safe, 1 = malicious)
#     return 0.2

# def analyze_text(text):
#     """Analyze the email body text for potential malicious content."""
#     # Implement text analysis logic here (e.g., using a pre-trained NLP model)
#     # Return a malicious content score between 0 and 1 (0 = safe, 1 = malicious)
#     return 0.3
api_keyy = os.getenv("API_KEYY")
def analyze_file(filename, content):
    """Analyze a file for potential malware."""
    # Example implementation using VirusTotal API
    api_key = api_keyy
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    files = {'file': (filename, content)}
    params = {'apikey': api_key}
    response = requests.post(url, files=files, params=params)
    
    if response.status_code == 200:
        result = response.json()
        scan_id = result['scan_id']
        report_url = f"https://www.virustotal.com/vtapi/v2/file/report?apikey={api_key}&resource={scan_id}"
        report_response = requests.get(report_url)
        
        if report_response.status_code == 200:
            report = report_response.json()
            positives = report.get('positives', 0)
            total = report.get('total', 1)
            return positives / total
    

def analyze_text(text):
    try:
        classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
        result = classifier(text)
        
        if result:
            score = result[0]['score']
            label = result[0]['label']
            return score if label == 'NEGATIVE' else 0
        return 0  # Default to 0 if no result
    
    except Exception as e:
        print(f"Error in text analysis: {e}")
        return 0

def classify_email(subject, from_addr, body, attachments, links):
    """Classify an email as malicious or benign."""
    subject_score = analyze_text(subject)
    from_score = analyze_text(from_addr)
    body_score = analyze_text(body)
    attachment_scores = analyze_attachments(attachments)
    link_scores = [analyze_text(link) for link in links]

    total_score = (
    subject_score + 
    from_score + 
    body_score + 
    (max(link_scores) if link_scores else 0) + 
    (max(score for _, score in attachment_scores) if attachment_scores else 0)
    ) / 5

    if total_score > 0.5:
        return "Malicious"
    else:
        return "Benign"

def report_email(email_info, classification):
    """Report the email classification to the user."""
    subject, from_addr, body, attachments, links = email_info
    st.write(f"Subject: {subject}")
    st.write(f"From: {from_addr}")
    st.write("Body:")
    st.write(body)
    st.write(f"Attachments: {', '.join([a.get_filename() for a in attachments])}")
    st.write(f"Links: {', '.join(links)}")
    st.write(f"Classification: {classification}")

def final():
    st.title("Email Security Scanner")

    host = st.text_input("IMAP Server Host", "imap.gmail.com")
    username = st.text_input("Email Username")
    password = st.text_input("Email Password", type="password")

    if st.button("Scan Inbox"):
        mail = connect_to_email(host, username, password)
        for msg in fetch_emails(mail):
            email_info = extract_email_features(msg)
            classification = classify_email(*email_info)
            report_email(email_info, classification)

                        
def main():
    st.title("🛡️ Network Flow-Based Intrusion Detection System")
    
    # Sidebar
    st.sidebar.header("Navigation")
    page = st.sidebar.selectbox("Choose a page", 
                               ["Home", "Training", "Live Detection", "Analytics", "Log Analysis","Threat Intelligence","Mail Security"])
    
    if page == "Home":
        st.markdown("""
        ## Welcome to Network Flow IDS
        This application analyzes network flow data to detect potential intrusions.
        
        ### Features:
        - Flow-based traffic analysis
        - Machine learning-based detection
        - Interactive visualizations
        - Real-time flow monitoring
        - Log parsing and analysis
        - Attack detection and reporting
        - Threat intelligence lookup
        
        ### Key Flow Metrics Analyzed:
        - Flow Duration
        - Packet Counts (Forward/Backward)
        - Packet Lengths
        - Inter-arrival Times (IAT)
        - Flow Patterns
        """)
        
        st.sidebar.title("Quick Actions")
        st.sidebar.write("Access the app's main features quickly:")
        
        if st.sidebar.button("View Analytics", key="analytics_btn"):
            st.session_state.page = "Analytics"
            
        
        if st.sidebar.button("Retrain Model", key="retrain_btn"):
            st.session_state.page = "Training"
        
        if st.sidebar.button("Live Detection", key="live_detection_btn"):
            st.session_state.page = "Live Detection"
        
        if st.sidebar.button("Log Analysis", key="log_analysis_btn"):
            st.session_state.page = "Log Analysis"

    elif page == "Training":
        st.header("Model Training")
        
        if st.button("Load and Process Data"):
            with st.spinner("Loading data..."):
                df = load_data()
                st.success(f"Loaded {len(df)} flow records!")
                
                st.subheader("Sample Flow Data")
                st.dataframe(df.head())
                
                df_processed = preprocess_data(df)
                X = df_processed.drop('Label', axis=1)
                y = df_processed['Label']
                
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=0.2, random_state=42)
                
                scaler = StandardScaler()
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)
                
                with st.spinner("Training model..."):
                    model = train_model(X_train_scaled, y_train)
                    
                with open('ids_model.pkl', 'wb') as f:
                    pickle.dump(model, f)
                with open('ids_scaler.pkl', 'wb') as f:
                    pickle.dump(scaler, f)
                
                y_pred = model.predict(X_test_scaled)
                
                st.subheader("Model Performance")
                st.text("Classification Report:")
                st.text(classification_report(y_test, y_pred))
                
                cm = confusion_matrix(y_test, y_pred)
                fig, ax = plt.subplots()
                sns.heatmap(cm, annot=True, fmt='d', ax=ax, 
                          xticklabels=['Benign', 'Malicious'],
                          yticklabels=['Benign', 'Malicious'])
                plt.xlabel('Predicted')
                plt.ylabel('True')
                st.pyplot(fig)
                
                importance_fig = create_feature_importance_plot(model, X.columns)
                st.plotly_chart(importance_fig)

    elif page == "Live Detection":
        live_detection()
        
        # try:
        #     with open('ids_model.pkl', 'rb') as f:
        #         model = pickle.load(f)
        #     with open('ids_scaler.pkl', 'rb') as f:
        #         scaler = pickle.load(f)
                
        #     if st.button("Start Flow Monitoring"):
        #         placeholder = st.empty()
        #         metrics_placeholder = st.empty()
        #         chart_placeholder = st.empty()
                
        #         flow_history = []
                
        #         for i in range(50):
        #             df = load_data()
        #             random_flow = df.iloc[np.random.randint(len(df))].copy()
        #             scaled_flow = scaler.transform(random_flow.drop('Label').values.reshape(1, -1))
        #             prediction = model.predict(scaled_flow)[0]
        #             prediction_prob = model.predict_proba(scaled_flow)[0]
                    
        #             flow_history.append({
        #                 'time': i,
        #                 'prediction': prediction,
        #                 'confidence': prediction_prob.max()
        #             })
                    
        #             with placeholder.container():
        #                 col1, col2, col3 = st.columns(3)
                        
        #                 with col1:
        #                     st.metric("Flow ID", f"#{i+1}")
        #                 with col2:
        #                     if prediction == 0:
        #                         st.success("Benign Flow")
        #                     else:
        #                         st.error("Suspicious Flow")
        #                 with col3:
        #                     st.metric("Confidence", f"{prediction_prob.max():.2%}")
                        
        #                 st.json({
        #                     'Flow Duration': f"{random_flow['Flow Duration']:.2f}",
        #                     'Fwd Packets': f"{random_flow['Total Fwd Packets']:.2f}",
        #                     'Bwd Packets': f"{random_flow['Total Backward Packets']:.2f}",
        #                     'Fwd Bytes': f"{random_flow['Total Length of Fwd Packets']:.2f}",
        #                     'Bwd Bytes': f"{random_flow['Total Length of Bwd Packets']:.2f}"
        #                 })
                    
        #             if len(flow_history) > 1:
        #                 history_df = pd.DataFrame(flow_history)
        #                 fig = px.line(history_df, x='time', y='confidence',
        #                             color=history_df['prediction'].astype(str),
        #                             title='Flow Analysis History',
        #                             color_discrete_map={'0': 'green', '1': 'red'})
        #                 chart_placeholder.plotly_chart(fig)
                    
        #             time.sleep(0.5)
                    
        # except FileNotFoundError:
        #     st.error("Please train the model first!")

    elif page == "Analytics":
        st.header("Flow Analytics Dashboard")
        
        try:
            df = load_data()
            
            col1, col2 = st.columns(2)
            
            with col1:
                label_counts = df['Label'].value_counts()
                fig = px.pie(values=label_counts.values, 
                            names=label_counts.index,
                            title='Flow Classification Distribution')
                st.plotly_chart(fig)
            
            with col2:
                fig = px.scatter(df, x='Total Fwd Packets', y='Total Backward Packets',
                               color='Label', title='Forward vs Backward Packets',
                               opacity=0.6)
                st.plotly_chart(fig)
            
            fig = px.histogram(df, x='Flow Duration', color='Label',
                             title='Flow Duration Distribution',
                             marginal='box')
            st.plotly_chart(fig)
            
            iat_cols = [col for col in df.columns if 'IAT' in col]
            iat_data = df[iat_cols + ['Label']]
            
            fig = px.box(iat_data.melt(id_vars=['Label'], 
                                     value_vars=iat_cols),
                        x='variable', y='value', color='Label',
                        title="IAT Analysis")
            st.plotly_chart(fig)
            
        except FileNotFoundError:
            st.error("Data is not loaded yet. Please load the data first!")

    elif page == "Log Analysis":
        st.header("Log Analysis and Reporting")
        
        st.subheader("Log Upload")
        uploaded_file = st.file_uploader("Choose a log file", type=["txt", "log"])
        if uploaded_file is not None:
            log_data = uploaded_file.getvalue().decode("utf-8")
            st.success("Log file uploaded successfully!")
            
            st.subheader("Log Analysis")
            analyze_logs(log_data)
            
            st.subheader("Attack Report")
            df = load_data()
            generate_attack_report(df)
            
            st.subheader("Log Search")
            search_term = st.text_input("Enter a search term:")
            if search_term:
                st.write(f"Search results for '{search_term}':")
                # Display relevant log entries
                
        else:
            st.info("Please upload a log file to get started.")
    elif page == "Threat Intelligence":
        # Call the function from threat_intelligence.py to display the threat intelligence lookup interface
        display_threat_intelligence()
    elif page == "Mail Security":
        final() 
    # st.sidebar.title("Application Settings")
    # st.sidebar.write("Customize the app's appearance and behavior:")
    # theme = st.sidebar.selectbox("Select a theme", ["Light", "Dark"])
    # if theme == "Dark":
    #     st.markdown("""
    #     <style>
    #     [data-theme="dark"] {
    #         --background-color: #1c1c1e;
    #         --text-color: #f2f2f2;
    #         --primary-color: #0077b6;
    #         --secondary-color: #00a8e8;
    #     }
    #     </style>
    #     """, unsafe_allow_html=True)
    # else:
    #     st.markdown("""
    #     <style>
    #     [data-theme="light"] {
    #         --background-color: #f2f2f2;
    #         --text-color: #1c1c1e;
    #         --primary-color: #0077b6;
    #         --secondary-color: #00a8e8;
    #     }
    #     </style>
    #     """, unsafe_allow_html=True)
        
    st.sidebar.write("---")
    st.sidebar.title("About")
    st.sidebar.write("Network Flow IDS v1.2")
    st.sidebar.write("Built with Streamlit, Plotly, and Scikit-learn")
    st.sidebar.write("Created by Team Fireshark")
    
    st.sidebar.write("---")
    st.sidebar.title("Feedback")
    with st.sidebar.form("feedback_form"):
        st.write("Let us know how we can improve!")
        feedback = st.text_area("Your feedback")
        submit = st.form_submit_button("Submit")
        if submit:
            if feedback.strip():
             save_feedback_to_csv(feedback)
             st.success("Thank you for your feedback! It has been saved.")
        else:
            st.warning("Feedback cannot be empty. Please provide your feedback.")
            
if __name__ == "__main__":
    if "page" not in st.session_state:
        st.session_state.page = "Home"
    main()
