FROM python:3-alpine

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container
COPY . /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port mcpo will use
EXPOSE 8000

# Run the MCP server using mcpo
CMD ["mcpo", "--port", "8000", "--", "python3", "vulners_mcp.py"]

