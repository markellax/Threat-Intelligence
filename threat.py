from PyQt5.QtWidgets import (
QApplication, QWidget, QLineEdit, QPushButton,
QVBoxLayout, QRadioButton, QLabel,QTextEdit)
import sys 
import requests
import ipaddress
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
import base64
from PyQt5.QtCore import QObject, pyqtSignal
import threading
import hashlib

load_dotenv()
api_key = os.getenv("api_key")

#create app
app = QApplication(sys.argv)

#create window
win = QWidget()

#QSS stylesheet
win.setStyleSheet("""

QWidget {
    background-color: #0F172A;;
    color: #F8FAFC;
    font-family: Arial;
    font-size: 14px;
}

QLineEdit {
    background-color: #1E293B;
    border: 1px solid #333;
    padding: 8px;
    border-radius: 6px;
    color: white;
}

QPushButton {
    background-color: #475569;
    border: none;
    padding: 10px;
    border-radius: 6px;
    color: white;
}

QPushButton:hover {
    background-color: #1E293B;
}

QRadioButton {
    font-size: 16px;
    padding: 6px;
}
                  
QRadioButton::indicator {
    width: 20px;
    height: 20px;
    border-radius: 10px;
    border: 2px solid #1E293B;
    background-color: #475569;
}

QRadioButton::indicator:checked {
    background-color: #475569;
    border: 2px solid #F8FAFC;
}""")


win.resize(1000, 500)
#window title
win.setWindowTitle('ThreatLens')

#title
lbl_input = QLabel("Indicator to Analyze")
lbl_input.setStyleSheet("color: white; " 
                        "font-size: 30px")

#textbox for input 
path_input = QLineEdit()
path_input.setPlaceholderText("Enter an IP address, domain, URL or filename")

#button
btn_check = QPushButton("Analyze")

#radio buttons
rb_ip = QRadioButton("IP Address")
rb_domain = QRadioButton("Domain")
rb_url = QRadioButton("URL")
rb_file = QRadioButton("FileName")
rb_ip.setChecked(True)

#result text
result_output = QTextEdit()
result_output.setReadOnly(True)
result_output.setPlaceholderText("")

#add widgets to layout
layout = QVBoxLayout()
layout.setSpacing(25)
layout.addWidget(lbl_input)
layout.addWidget(path_input)
layout.addWidget(rb_ip)
layout.addWidget(rb_domain)
layout.addWidget(rb_url)
layout.addWidget(rb_file)
layout.addWidget(result_output)
layout.addWidget(btn_check)
win.setLayout(layout)

# Handles communication between the background thread and the GUI thread.
# Sends results to the GUI safely using a Qt signal.
class Communicator(QObject):
    result_ready = pyqtSignal(str)
communicator = Communicator()
communicator.result_ready.connect(result_output.setPlainText)


def check_ip(ip):
    ip = ipaddress.ip_address(ip)
    headers = {"accept": "application/json","x-apikey": api_key}
    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers,timeout=15)
    r.raise_for_status()
    data = r.json()
    data = data["data"]["attributes"]
    return data


def check_domain(domain):
    if not domain.startswith("https://") and not domain.startswith("http://"):
        domain = "https://" + domain
    else:
        pass
    domain = urlparse(domain).hostname
    headers = {"accept": "application/json","x-apikey": api_key}
    r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers,timeout=15)
    r.raise_for_status()
    data = r.json()
    data = data["data"]["attributes"]
    return data


def check_url(url):
    url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"accept": "application/json","x-apikey": api_key}
    r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers,timeout=15)
    r.raise_for_status()
    data = r.json()
    data = data["data"]["attributes"]
    return data

def check_hash(filename):
    with open(filename.strip('"'), "rb") as file:
        file_hash = hashlib.sha256(file.read()).hexdigest()
    headers = {"accept": "application/json","x-apikey": api_key}
    r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers,timeout=15)
    r.raise_for_status()
    data = r.json()
    data = data["data"]["attributes"]
    return data

def on_analyze():
    if not api_key:
        communicator.result_ready.emit("API key missing. Check your .env file.")
        return
    value = path_input.text().strip()
    if rb_ip.isChecked():
        try:
            result = check_ip(value)
            stats = result["last_analysis_stats"]
            communicator.result_ready.emit(str(stats).replace("{", "").replace("}", "").replace("'", ""))
        except ValueError:
            communicator.result_ready.emit("Invalid IP address or invalid JSON response.")
        except requests.exceptions.RequestException:
            communicator.result_ready.emit("API request failed. Check your connection and API access.")
    elif rb_domain.isChecked():
        try:
            result = check_domain(value)
            stats = result["last_analysis_stats"]
            communicator.result_ready.emit(str(stats).replace("{", "").replace("}", "").replace("'", ""))
        except ValueError:
                communicator.result_ready.emit("Invalid Domain Address or invalid JSON response.")
        except requests.exceptions.RequestException:
                communicator.result_ready.emit("API request failed. Check your connection and API access.")
    elif rb_file.isChecked():
        try:
            result = check_hash(value)
            stats = result["last_analysis_stats"]
            communicator.result_ready.emit(str(stats).replace("{", "").replace("}", "").replace("'", ""))
        except ValueError:
            communicator.result_ready.emit("Invalid Hash File or invalid JSON response.")
        except requests.exceptions.RequestException:
            communicator.result_ready.emit("API request failed. Check your connection and API access.")
    elif rb_url.isChecked():
        try:
            result = check_url(value)
            stats = result["last_analysis_stats"]
            communicator.result_ready.emit(str(stats).replace("{", "").replace("}", "").replace("'", ""))
        except ValueError:
            communicator.result_ready.emit("Invalid URL Link or invalid JSON response.")
        except requests.exceptions.RequestException:
            communicator.result_ready.emit("API request failed. Check your connection and API access.")
    else:
        print("An error has occured!!")

def start_process():
    thread = threading.Thread(target=on_analyze)
    thread.start()
btn_check.clicked.connect(start_process)

win.show() #app's window is shown
sys.exit(app.exec_())#keeps app opened