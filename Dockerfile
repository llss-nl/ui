# Use the official Python image from the Docker Hub
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .
COPY main.py .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Command to run the application
CMD ["python", "main.py"]
