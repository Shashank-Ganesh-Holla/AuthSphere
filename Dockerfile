# Use an official Python base image
FROM python:3.11-slim 

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt 

# Copy rest of the application
COPY . .

# Expose port 8000 for FastAPI 
EXPOSE 8000 

# Run the FastAPI app using Uvicorn

CMD ["uvicorn", "auth_app.main:app", "--host", "0.0.0.0", "--port", "8000"]