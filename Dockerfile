# Use the official Python image from the Docker Hub
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY . .

# Install the dependencies
RUN pip install /app/

# Command to run the application
CMD ["firewall_block"]
