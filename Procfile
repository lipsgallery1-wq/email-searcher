web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 600 --max-requests 1000 --max-requests-jitter 50 --worker-class sync
