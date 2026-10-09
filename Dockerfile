# Stage 7: one-command deploy. Employers click links, not READMEs.
# Build trains models INSIDE the image so the demo works with zero setup.
FROM python:3.12-slim

WORKDIR /app

# Install deps first (cached unless requirements change)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code + 24k CSV, train models during build
COPY config.py feature_extractor.py train_model.py explainer.py database.py app.py ./
COPY data/ ./data/
COPY templates/ ./templates/
COPY static/ ./static/
RUN python train_model.py --full

EXPOSE 5000
ENV PORT=5000 FLASK_DEBUG=0
# 2 workers is enough for a demo; health check at /health
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60"]
