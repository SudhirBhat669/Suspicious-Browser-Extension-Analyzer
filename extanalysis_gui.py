import os
import re
import json
import zipfile
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from collections import defaultdict
import matplotlib.pyplot as plt
from PIL import ImageGrab
import folium
from fpdf import FPDF
import requests

SUSPICIOUS_PATTERNS = {
    "IPv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "IPv6": r"\b(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}\b",
    "URL": r"https?://[^\s\"'>]+",
    "Email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "BTC Address": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "Base64": r"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
}

ALLOWED_FILE_TYPES = ('.js', '.json', '.html', '.css')

def analyze_extension(file_path):
    findings = defaultdict(set)
    try:
        with zipfile.ZipFile(file_path, 'r') as archive:
            for file in archive.namelist():
                if file.endswith(ALLOWED_FILE_TYPES):
                    with archive.open(file) as f:
                        content = f.read().decode(errors="ignore")
                        for label, pattern in SUSPICIOUS_PATTERNS.items():
                            matches = re.findall(pattern, content)
                            findings[label].update(matches)
    except zipfile.BadZipFile:
        messagebox.showerror("Error", "Invalid ZIP/Extension file format!")
    return findings

def geoip_lookup(ip_or_url):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_or_url}").json()
        return response.get("lat"), response.get("lon"), response.get("city")
    except:
        return None, None, None

def create_map(findings):
    m = folium.Map(location=[20,0], zoom_start=2)
    if "IPv4" in findings:
        for ip in findings["IPv4"]:
            lat, lon, city = geoip_lookup(ip)
            if lat and lon:
                folium.Marker(location=[lat, lon], popup=f"{ip} ({city})").add_to(m)
    if "URL" in findings:
        for url in findings["URL"]:
            try:
                domain = url.split("/")[2]
                lat, lon, city = geoip_lookup(domain)
                if lat and lon:
                    folium.Marker(location=[lat, lon], popup=f"{domain} ({city})", icon=folium.Icon(color="green")).add_to(m)
            except:
                continue
    os.makedirs("assets", exist_ok=True)
    m.save("assets/extanalysis_map.html")

def generate_graph(findings):
    labels = list(findings.keys())
    values = [len(findings[k]) for k in labels]
    if values:
        plt.figure(figsize=(8, 4))
        plt.bar(labels, values, color="purple")
        plt.title("Suspicious Patterns Found")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        os.makedirs("assets", exist_ok=True)
        plt.savefig("assets/extanalysis_graph.png")
        plt.close()

def capture_gui(win):
    x = win.winfo_rootx()
    y = win.winfo_rooty()
    w = win.winfo_width()
    h = win.winfo_height()
    img_path = "assets/extanalysis_gui_screenshot.png"
    ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(img_path)
    return img_path

def generate_pdf_report(findings):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="ExtAnalysis Report", ln=True, align='C')
    for category, items in findings.items():
        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(200, 10, txt=f"{category}:", ln=True)
        pdf.set_font("Arial", size=10)
        for item in items:
            pdf.multi_cell(0, 8, txt=item)
    if os.path.exists("assets/extanalysis_graph.png"):
        pdf.image("assets/extanalysis_graph.png", w=180)
    pdf.output("assets/extanalysis_report.pdf")

def create_gui():
    root = tk.Tk()
    root.title("ExtAnalysis GUI")
    root.geometry("1000x700")
    root.configure(bg="#1e1e1e")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="#252526", foreground="white", fieldbackground="#252526", font=('Arial', 10))
    style.configure("Treeview.Heading", background="#007acc", foreground="white", font=('Arial', 11, 'bold'))

    label = tk.Label(root, text="ExtAnalysis - Suspicious Extension Analyzer", bg="#1e1e1e", fg="white", font=("Arial", 16))
    label.pack(pady=10)

    tree = ttk.Treeview(root, columns=("Type", "Details"), show="headings")
    tree.heading("Type", text="Type")
    tree.heading("Details", text="Suspicious Data")
    tree.column("Type", width=150)
    tree.column("Details", width=700)
    tree.pack(pady=10, fill="both", expand=True)

    def browse_file():
        file_path = filedialog.askopenfilename(filetypes=[("Extension Files", "*.zip *.crx *.xpi")])
        if not file_path:
            return
        tree.delete(*tree.get_children())
        results = analyze_extension(file_path)
        total = 0
        for category, items in results.items():
            for item in items:
                tree.insert("", "end", values=(category, item))
                total += 1
        if total > 0:
            messagebox.showinfo("Scan Complete", f"{total} suspicious entries found.")
        else:
            messagebox.showinfo("Scan Complete", "No suspicious data found.")
        generate_graph(results)
        create_map(results)
        capture_gui(root)
        generate_pdf_report(results)

    btn = tk.Button(root, text="Upload & Scan Extension (.zip/.crx/.xpi)", font=("Arial", 12), bg="#007acc", fg="white", command=browse_file)
    btn.pack(pady=10)
    root.mainloop()

if __name__ == "__main__":
    create_gui()
