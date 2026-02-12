#!/bin/bash
# Deploy script for the weather service

# Download latest config
curl -s https://api.config-server.com/v1/config -o /tmp/config.json

# Copy artifacts
cp ./build/app.tar.gz /opt/deploy/
chmod 755 /opt/deploy/app.tar.gz

# Run deployment via docker
docker build -t weather-app .
docker push registry.example.com/weather-app:latest

# Apply k8s manifests
kubectl apply -f ./k8s/deployment.yaml

# Use credentials
aws s3 cp s3://artifacts-bucket/release.tar.gz ./
echo "Using token: $API_KEY"
echo "DB password: $DB_PASSWORD"
