@echo off
TITLE Follow O-I
echo Follow O-I wordt gestart...
python -m pip install -r requirements.txt
start "" http://127.0.0.1:5000
python app.py
pause
