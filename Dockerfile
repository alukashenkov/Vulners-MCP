# Stage 1: Download and extract CAPEC taxonomy data
FROM alpine:latest AS capec-downloader

# Install tools needed for downloading and extracting
RUN apk add --no-cache wget unzip

# Download and extract CAPEC taxonomy data (MITRE's Common Attack Pattern Enumeration and Classification)
# This provides the 1000.xml file needed for CAPEC attack pattern name resolution and taxonomy mappings
RUN wget -O /tmp/1000.xml.zip https://capec.mitre.org/data/xml/views/1000.xml.zip && \
    unzip /tmp/1000.xml.zip -d /tmp && \
    ls -la /tmp/1000.xml

# Stage 2: Final runtime image
FROM python:3-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Copy the extracted CAPEC taxonomy file from the previous stage
COPY --from=capec-downloader /tmp/1000.xml /app/1000.xml

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Verify the CAPEC file is in place and show its size
RUN ls -la /app/1000.xml && echo "CAPEC taxonomy file successfully installed"

# Expose the port mcpo will use
EXPOSE 8000

# Run the MCP server using mcpo
CMD ["mcpo", "--port", "8000", "--", "python3", "vulners_mcp.py"]

