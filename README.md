# if4020-tugas5

Setup:
1. Jalankan `pip install flask`
2. Jalankan `pip install flask_socketio`
3. Jalankan `pip install python-dotenv`
4. Import `client/crypto.sql`
5. Duplicate `client/.env.example` menjadi `client/.env` dan sesuaikan dengan env terkait

Cara menjalankan server;
1. Jalankan `cd server/`
2. Jalankan `flask --app app.py --debug run -p 3000`

Cara menjalankan client:
1. Jalankan `cd client/`
2. Jalankan `flask --app app.py --debug run -p [PORT]`
3. Website dapat diakses pada `http://127.0.0.1:[PORT]/`
