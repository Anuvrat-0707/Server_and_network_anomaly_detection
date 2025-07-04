# Anomaly Detection in Server and Network

Monitors system and network metrics, logs data, and uses Isolation Forest to detect anomalies.#   S e r v e r A n o m a l y D e t e c t i o n 
 
 #   S e r v e r A n o m a l y D e t e c t i o n 
 
 # ⚠️ Server and Network Anomaly Detection Dashboard

A Python-Flask-based intelligent dashboard that monitors and detects anomalies in server metrics and network behavior using Machine Learning (ML) models and Large Language Model (LLM) explanations.

---

## 📌 Features

- 🔍 **Binary & Multiclass Anomaly Detection**
- 📊 **Interactive Dashboard** with DataTables and Charts
- ⚙️ **System Resource Monitoring** (CPU, Memory, Disk)
- 🌐 **Port & IP Traffic Analysis**
- 🧠 **Groq LLM Integration** for Explanation of Anomalies
- 📤 **Manual Input Form** for Custom Prediction
- 🗂️ Organized structure for `network`, `server`, and `shared` components

---

## 🧠 Project Motivation

This project was built to identify and explain abnormal behavior in system performance or network traffic using ML models and real-time data — critical for security, maintenance, and infrastructure monitoring.

---

## 🛠️ Tech Stack

- **Frontend**: HTML5, CSS3, Bootstrap, DataTables
- **Backend**: Python, Flask
- **ML Models**: Trained Scikit-learn models (`.pkl` files)
- **LLM**: Groq API for contextual anomaly explanation
- **System APIs**: `psutil`, `win32evtlog` for system log and metrics

---

## 🗂️ Project Structure

.
├── main.py # Main entry point
├── server_anomaly/ # Server anomaly detection code
│ ├── dashboard_server.py
│ ├── utils_server.py
│ └── templates/
├── network_anomaly/ # Network anomaly detection code
│ ├── dashboard_network.py
│ ├── utils_network.py
│ └── templates/
├── shared/ # Shared utilities and LLM interface
│ ├── app.py
│ ├── llm/
│ └── data/
├── data/ # Datasets and logs
├── requirements.txt
├── .env (not tracked)
└── README.md

yaml
Copy
Edit

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/Anuvrat-0707/Server_and_network_anomaly_detection.git
cd Server_and_network_anomaly_detection
2. Create a Virtual Environment (Optional but Recommended)
bash
Copy
Edit
python -m venv env
source env/bin/activate    # or .\env\Scripts\activate on Windows
3. Install Dependencies
bash
Copy
Edit
pip install -r requirements.txt
4. Configure Environment Variables
Create a .env file:

env
Copy
Edit
GROQ_API_KEY=your_groq_api_key_here
5. Run the Application
bash
Copy
Edit
python main.py
📈 Datasets
Train.txt and Test.txt: Network traffic logs

server_log.csv: Server resource usage metrics

log.csv: Central event & anomaly log

🧪 How It Works
Data Ingestion – Read from CSV or real-time system calls

Prediction – Apply binary/multiclass ML models

Explanation – Call Groq API to generate a natural-language reason

Display – Show results on a responsive Flask dashboard

🔒 Security Note
Secrets like API keys are excluded via .gitignore. Do not hardcode your Groq API key.

📸 Screenshots
Include screenshots of the dashboard interface, manual prediction, and LLM explanation here.

🧑‍💻 Author
Anuvrat Saxena – @Anuvrat-0707

📄 License
This project is licensed under the MIT License – see the LICENSE file for details.

🙋‍♂️ Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
