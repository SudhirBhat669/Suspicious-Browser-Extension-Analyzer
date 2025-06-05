# 🔍 Suspicious-Browser-Extension-Analyzer
## GUI Screenshot
![Image](https://github.com/user-attachments/assets/fb017ec3-1ea7-48b4-9ff3-9d516620c501)

## Graph Screenshot
![Image](https://github.com/user-attachments/assets/1e3d3851-6b0d-4ceb-87c2-627fdffdd122)

## 🧠 Objective
To develop a Python-based GUI application that identifies potentially harmful browser extensions by scanning .crx, .xpi, and .zip packages using pattern-matching and visualization techniques. This tool helps improve browser security awareness and provides actionable insights through graphing, Geo-IP visualization, and exportable reports.

## 🎯 Outcome
Identify suspicious patterns in browser extension files.
Visualize suspicious data via bar graphs.
Display extracted IPs and domains on an interactive map.
Export findings and GUI snapshots to PDF reports.
Promote awareness of browser security threats.

## 🔑 Key Concepts
Browser extension internals (manifest files, scripts).
Regular expressions for threat pattern extraction.
File extraction from ZIP, CRX, XPI.
Geo-IP Mapping using folium.
GUI Development with Tkinter.
Graphing with matplotlib.
Screenshot capture with PIL.ImageGrab.
PDF report generation with FPDF.

## ⚙️ How It Was Done
GUI built using Tkinter with styled Treeview to show scan results.
zipfile is used to open and extract files inside extensions.
Suspicious data (IPs, emails, URLs, BTC addresses, etc.) is extracted using regex.
Extracted IPs/domains are mapped using Folium on an interactive HTML map.
Graph of findings is plotted with matplotlib.
Screenshot of GUI and findings are exported to a PDF using FPDF.

## 📥 How Do I Install It?
1. Clone the repository or download the ZIP.
2. Install dependencies
bash
pip install -r requirements.txt
3. Ensure you have Python 3.7 or later.

## 🚀 How Do I Use It?
1. Run the app
bash
python extanalysis_gui_geo_pdf.py

2. Click the "Upload & Scan Extension" button.
3. Choose a .zip, .crx, or .xpi file.
4. The GUI will display suspicious findings in a table.
5. A graph will be generated.
6. A Geo-IP map (if applicable) and PDF report will be saved in the assets/ directory.

## ❓ Interview Questions 
1. What is ExtAnalysis?
2. How does ExtAnalysis detect suspicious patterns?
3. Which formats does it support?
4. What libraries are used for visualization?
5. How does it generate reports?
6. Can it scan real installed browser extensions?
7. What is the use of Folium here?
8. Is the tool safe to use?
9. How does it handle invalid files?
10. What are common patterns found in malicious extensions?
11. Can this be converted to CLI?

## 📦 Files Created
assets/extanalysis_graph.png – Graph of patterns found.
assets/extanalysis_gui_screenshot.png – GUI screenshot.
assets/extanalysis_report.pdf – PDF report with results and graph.
geo_map.html – IP/domain location map.

## ✅ Summary
ExtAnalysis empowers users to analyze, visualize, and report potentially malicious browser extensions with a few clicks. Ideal for cybersecurity learners, digital forensic analysts, or browser power users.


