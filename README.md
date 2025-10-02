## Instalasi

1. Clone repositori:

   ```bash
   git clone https://github.com/windrase/dingdong.git
   cd dingdong
   ```

2. Buat virtual environment (opsional tapi disarankan):

   ```bash
   python3 -m venv venv
   source venv/bin/activate    # di Linux / macOS
   venv\Scripts\activate       # di Windows
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Duplicate file `.env.example` menjadi `.env`, lalu isi variabel-variabel yang dibutuhkan:

   Contoh variabel di `.env`:

   ```
   TELEGRAM_TOKEN=isi_token_bot_kamu
   # variabel-lain seperti API_KEY, SECRET_KEY, dsb
   ```

5. Jalankan bot:

   ```bash
   python dor.py
   ```
