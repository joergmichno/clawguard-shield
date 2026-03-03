FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory for SQLite
RUN mkdir -p /app/data

# Non-root user for security
RUN useradd -r -s /bin/false shield && chown -R shield:shield /app
USER shield

EXPOSE 5001

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5001", "--timeout", "30", "--access-logfile", "-", "app:app"]
