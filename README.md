# Proactive Cyber Deception

A cyber deception dashboard and analytics platform built with Flask, MongoDB, and machine learning. The project ingests honeypot event data, predicts attacker behavior, and displays live monitoring and investigation tools.

## Features

- Flask web dashboard with authentication
- MongoDB-backed data storage and thread-safe access
- Live attack and honeypot event monitoring
- ML-based attack prediction and risk scoring
- AI prevention advice for detected threats
- Admin and analyst access controls
- Socket.IO-powered real-time updates

## Getting Started

### Prerequisites

- Python 3.11+ or compatible Python 3 environment
- MongoDB running locally or accessible via `MONGO_URI`
- A `.env` file with required environment variables

### Install dependencies

```bash
pip install -r requirements.txt
```

### Configure environment

Create a `.env` file at the project root with at least:

```env
SECRET_KEY=your-secret-key
MONGO_URI=mongodb://localhost:27017/
PORT=5000
```

### Run the app

```bash
python run_flask.py
```

Then visit `http://localhost:5000`.

## Git LFS

This repository is configured to use Git LFS for large files in:

- `data/beth/raw/*.csv`
- `models/*.safetensors`
- `models/*.bin`
- `models/*.h5`
- `models/*.pkl`

If you add large files, make sure Git LFS is installed and enabled locally.

```bash
git lfs install --local
```

## Notes

- Do not commit `.env` or secrets to the repository.
- Large raw data files may be excluded from the repository to avoid GitHub size limits.
- Use `git status` to review changes before pushing.
