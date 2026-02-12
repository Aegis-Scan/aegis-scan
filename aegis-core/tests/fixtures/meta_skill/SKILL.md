# MLOps Training Pipeline

A production-grade machine learning skill that handles end-to-end ML workflows
including training, evaluation, and deployment to cloud infrastructure.

## Capabilities

- **Data ingestion** from PostgreSQL, MongoDB, and S3 buckets
- **Model training** using PyTorch and scikit-learn
- **Experiment tracking** with MLflow and Prometheus monitoring
- **Deployment** to Kubernetes via Helm charts and Docker containers
- **CI/CD** via GitHub Actions with automated testing (pytest)

## Usage

Run the training pipeline:
```bash
python scripts/train.py --config config.yaml
```

Evaluate a trained model:
```bash
python scripts/evaluate.py --model models/latest.pt --data data/test.csv
```

Health check:
```bash
python scripts/health_check.py
```

Deploy to production:
```bash
kubectl apply -f k8s/deployment.yaml
helm upgrade --install mlops ./charts/mlops
```

## Configuration

Edit `config.yaml` to set your database connections, S3 bucket paths,
and Kubernetes namespace.

## Requirements

The skill runs using the environment's Python installation.
