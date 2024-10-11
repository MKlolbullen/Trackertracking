import sys
import requests
from bs4 import BeautifulSoup
import re
import socket
import whois
import networkx as nx
import json
import urllib3
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget,
    QPushButton, QLineEdit, QTextEdit, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWebEngineWidgets import QWebEngineView
import plotly.graph_objs as go
import plotly.io as pio

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AnalyzeThread(QThread):
    result_signal = pyqtSignal(dict, str, list)

    def __init__(self, url, parent=None):
        super().__init__(parent)
        self.url = url
        self.parent = parent  # Reference to TrackingAnalyzer instance

    def run(self):
        connections, website_node, scripts = self.main_analysis(self.url)
        self.result_signal.emit(connections, website_node, scripts)

    def extract_tracking_scripts(self, url):
        """
        Extracts tracking script URLs and cookies from a given website.
        Identifies common trackers like Google, Facebook, LinkedIn, and others.
        """
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(url, headers=headers, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # List of common tracker patterns
            common_trackers = [
                "google-analytics", "googletagmanager", "facebook", "linkedin", "twitter",
                "doubleclick", "adservice", "adsystem", "pixel", "analytics", "track",
                "collect", "cdn.segment", "adroll", "hotjar", "mixpanel", "optimizely",
                "cloudflareinsights", "newrelic", "appdynamics"
            ]

            # Extract script sources
            scripts = []
            for script in soup.find_all('script', src=True):
                script_src = script['src']
                if any(tracker in script_src.lower() for tracker in common_trackers):
                    full_url = script_src if script_src.startswith('http') else requests.compat.urljoin(url, script_src)
                    scripts.append(full_url)

            cookies = response.cookies.get_dict()
            return scripts, cookies
        except Exception:
            return [], {}

    def resolve_ip(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except Exception:
            return None

    def get_company_info(self, domain):
        try:
            w = whois.whois(domain)
            org = w.org if w.org else w.name
            return org
        except Exception:
            return None

    def analyze_script(self, script_url):
        domain = self.parent.extract_domain_from_url(script_url)
        ip = self.resolve_ip(domain)
        company_info = self.get_company_info(domain)
        return {"ip": ip, "company": company_info}

    def main_analysis(self, url):
        scripts, _ = self.extract_tracking_scripts(url)
        connections = {}
        if not scripts:
            return connections, self.parent.extract_domain_from_url(url), scripts

        for script in scripts:
            info = self.analyze_script(script)
            connections[script] = info

        website_node = self.parent.extract_domain_from_url(url)
        return connections, website_node, scripts

class TrackingAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Tracking Analysis Tool')
        self.setGeometry(100, 100, 1000, 800)

        main_layout = QVBoxLayout()
        self.url_input = QLineEdit(self)
        self.url_input.setPlaceholderText('Enter a website URL...')
        main_layout.addWidget(self.url_input)

        analyze_button = QPushButton('Analyze URL', self)
        analyze_button.clicked.connect(self.analyze_single_url)
        main_layout.addWidget(analyze_button)

        batch_button = QPushButton('Select Batch File', self)
        batch_button.clicked.connect(self.select_batch_file)
        main_layout.addWidget(batch_button)

        self.output_area = QTextEdit(self)
        self.output_area.setReadOnly(True)
        main_layout.addWidget(self.output_area)

        self.graph_view = QWebEngineView(self)
        main_layout.addWidget(self.graph_view)

        central_widget = QWidget()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def log_message(self, message):
        self.output_area.append(message)
        self.output_area.ensureCursorVisible()

    def analyze_single_url(self):
        url = self.url_input.text().strip()
        if url:
            self.log_message(f'Processing {url}...\n')
            self.thread = AnalyzeThread(url, parent=self)
            self.thread.result_signal.connect(self.display_results)
            self.thread.start()

    def select_batch_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select Batch File', '', 'Text Files (*.txt)')
        if file_path:
            self.process_batch_file(file_path)

    def process_batch_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f.readlines() if line.strip()]

            for url in urls:
                self.log_message(f'Processing {url}...\n')
                self.thread = AnalyzeThread(url, parent=self)
                self.thread.result_signal.connect(self.display_results)
                self.thread.start()
        except Exception as e:
            self.log_message(f'Failed to process batch file {file_path}: {e}')

    def display_results(self, connections, website_node, scripts):
        if not scripts:
            self.log_message('No tracking scripts found.\n')
            return

        self.log_message(f'Found {len(scripts)} tracking scripts.\n')
        self.visualize_tracking_data(scripts, connections, website_node)

    def extract_domain_from_url(self, url):
        """
        Extracts the domain name from a URL.
        """
        domain = re.sub(r'^https?://', '', url).split('/')[0]
        domain = domain.split(':')[0]  # Remove port if present
        return domain

    def visualize_tracking_data(self, scripts, connections, website_node):
        nodes = list(set([website_node] + [self.extract_domain_from_url(script) for script in scripts] +
                         [info.get("ip", "Unknown IP") for info in connections.values()]))
        edges = []

        for script, info in connections.items():
            script_node = self.extract_domain_from_url(script)
            ip_node = info.get("ip", "Unknown IP")
            edges.append((website_node, script_node))
            edges.append((script_node, ip_node))

        G = nx.Graph()
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)
        pos = nx.spring_layout(G)

        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        node_x = []
        node_y = []
        node_text = []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=1, color='#888'),
            hoverinfo='none',
            mode='lines'
        )

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            text=node_text,
            mode='markers+text',
            textposition='top center',
            marker=dict(size=20, color='lightblue'),
            textfont=dict(size=10)
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title="Tracking Data Flow Visualization",
                showlegend=False,
                hovermode='closest',
                margin=dict(b=0, l=0, r=0, t=40),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
        )

        self.display_plot(fig)

    def display_plot(self, fig):
        html = pio.to_html(fig, full_html=False)
        self.graph_view.setHtml(html)

def main():
    app = QApplication(sys.argv)
    window = TrackingAnalyzer()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
