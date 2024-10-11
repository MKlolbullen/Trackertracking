# Trackertracking
Got the idea from Ghostery to do some tracking script/cookie analysis and of course visualization of it. It's a WIP but a fun start.
# Tracking Analysis Tool

This is a PyQt-based GUI application for analyzing tracking scripts on websites. It identifies common trackers (e.g., Google Analytics, Facebook Pixel) and visualizes the data flow between websites, tracking scripts, and associated IPs. The tool uses Plotly for interactive visualizations, which are embedded directly within the PyQt application.

## Features

- **URL Tracking Analysis**: Analyze a single URL for tracking scripts and display the results in an interactive graph.
- **Batch Processing**: Analyze multiple URLs from a text file in one go.
- **Data Flow Visualization**: Use Plotly to visualize relationships between the main website, tracking scripts, and associated IPs.
- **Integrated GUI**: Built with PyQt5, providing a user-friendly interface for entering URLs, batch processing, and displaying results.

## Prerequisites

Make sure you have the required Python packages installed:

- `Python 3.12`
- `requests`
- `beautifulsoup4`
- `networkx`
- `plotly`
- `PyQt5`
- `PyQtWebEngine`
- `whois`

You can install the dependencies using `pip`:

`pip install requests beautifulsoup4 networkx plotly PyQt5 PyQtWebEngine whois`

Installation

  Clone the repository:

` git clone https://github.com/yourusername/tracking-analysis-tool.git
  cd tracking-analysis-tool`

Install dependencies (if not already done):

`pip install -r requirements.txt`

If the requirements.txt file is not available, install dependencies manually using:

`pip install requests beautifulsoup4 networkx plotly PyQt5 PyQtWebEngine whois`

### Usage

   Run the application:

   `python trackingtrackers.py`

  Analyze a single URL:
        Enter a URL in the text field and click "Analyze URL" to analyze tracking scripts for a single website.

  Batch processing of URLs:
        Click "Select Batch File" to choose a text file containing multiple URLs (one URL per line).
        The application will process each URL and display the results.

  View interactive visualization:
        The visualization will appear in the embedded Plotly graph within the application.
        The graph displays the relationships between the website, tracking scripts, and associated IPs.

Features in Detail

  Tracking Script Detection:
        The tool identifies commonly used trackers like Google Analytics, Facebook Pixel, Twitter, LinkedIn, etc.
        It parses the website content to find known tracking script patterns and cookies.

   IP Resolution and WHOIS Information:
        The tool resolves the IP address for each tracking domain and performs a WHOIS lookup to find the associated company.

  Interactive Data Visualization:
        The visualization uses NetworkX and Plotly to represent the data flow.
        Nodes represent the website, tracking scripts, and IPs, while edges show the relationships.

Troubleshooting

   QSocketNotifier: Can only be used with threads started with QThread Warning:
        This error is addressed by using QThread for multi-threading. Ensure you are using the latest version of the code.

  inotify_add_watch Permission Denied:
        This warning is related to system-level permissions and can typically be ignored unless it affects functionality.

   qt.qpa.wayland: Wayland does not support QWindow::requestActivate():
        This is related to the Wayland display server. It may not cause issues but can be avoided by switching to the X11 display server if necessary.

  Core Dump or Application Crash:
        Ensure all dependencies are installed and up to date. If the problem persists, try running the script with elevated privileges.

Development

To contribute to the project, please follow these steps:

  Fork the repository and create your branch from main.
    Clone your fork locally:

`git clone https://github.com/yourusername/tracking-analysis-tool.git
 cd tracking-analysis-tool`

Create a new branch for your feature:

`git checkout -b feature/my-new-feature`

Commit your changes and push to your fork:

    git add .
    git commit -m "Add some feature"
    git push origin feature/my-new-feature

  Create a pull request from your fork on GitHub.

License

This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgements

   The application uses Plotly for interactive data visualization.
    NetworkX is used for graph data structures and algorithms.
    PyQt5 provides the GUI framework and embedded web engine support.

# Disclaimer

- Use this tool responsibly. Be aware of website terms of service and data privacy laws in your region when performing tracking analysis. The authors are not responsible for any misuse of the tool.


Thank you for using the Tracking Analysis Tool! If you have any questions, feel free to open an issue or contact the authors.
