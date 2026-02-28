FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for Playwright and other tools
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install python packages
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Install the aura-framework
RUN pip install --no-cache-dir -e .

# Install Playwright browsers (chromium only to save space/time)
RUN playwright install --with-deps chromium

# Create a non-root user for executing the tool
RUN useradd -m aurauser && chown -R aurauser /app
USER aurauser

# Default command (can be overridden)
ENTRYPOINT ["aura"]
CMD ["--help"]
