FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_HOME=/app

# Set the working directory
WORKDIR $APP_HOME

# Install system dependencies (if needed, e.g., for certain Python packages or network tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose the port the web app runs on (matching web_app.py default)
EXPOSE 5000

# Specify the default command to run the web application
CMD ["python", "main.py"]
