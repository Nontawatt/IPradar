FROM python:3.10-slim

# Install nmap for scanning
RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ipradar.py README.md /app/
RUN pip install --no-cache-dir -r requirements.txt

# Environment variables for API keys (can be overridden at runtime)
ENV SHODAN_API_KEY=""
ENV CENSYS_API_ID=""
ENV CENSYS_API_SECRET=""

ENTRYPOINT ["python", "ipradar.py"]
CMD ["--help"]
