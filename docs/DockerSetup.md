# 🐳 Running C-H-A-R-L-O-T-T-E in Docker

This guide helps contributors run and develop CHARLOTTE inside a Docker container, ensuring a consistent Python and dependency environment across platforms.

---

## 📦 Requirements

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- Git (for cloning CHARLOTTE)
- Python (optional outside the container)

---

## 🗂️ Project Structure

Make sure your project has this structure:

``` plaintext
C-H-A-R-L-O-T-T-E/
├── core/
├── agents/
├── plugins/
├── data/
├── requirements.txt
├── Dockerfile 👈 Create this
└── docker-compose.yml 👈 Optional, for advanced usage
```
---

## 🛠️ Step 1: Create a `Dockerfile`

In the CHARLOTTE root directory:

```Dockerfile
# Dockerfile

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Default command (can be overridden)
CMD ["python", "core/main.py"]

```
---

## 🛠️ Step 2: (Optional) Add `.dockerignore`

``` plaintext
__pycache__/
*.pyc
*.pyo
*.pyd
.venv/
.env
data/
```
---

## 🚀 Step 3: Build the Docker Image

From the CHARLOTTE root:

``` command
docker build -t charlotte-dev .
```
---

## ▶️ Step 4: Run CHARLOTTE in Docker

``` command
docker run -it --rm charlotte-dev
```
If your `core/main.py` launches CHARLOTTE's CLI, it will run interactively inside the container.

---

## 🛠️ Optional: Run with Volume Mounting (Live Code Reloading)

This allows changes to your code to reflect immediately in the container without rebuilding.


To map your local CHARLOTTE code into the container:

``` command
docker run -it --rm -v ${PWD}:/app charlotte-dev
```

On Windows (PowerShell):

``` PowerShell command
docker run -it --rm -v ${PWD}:/app charlotte-dev
```
---

## 🧪 Running Tests in Docker

``` command
docker run -it --rm charlotte-dev pytest tests/
```
---

## 🧵 Troubleshooting

Example of how to add auth passing to docker container:
- Hugging Face Login: If datasets requires authentication, you can pass environment variables:
``` command
docker run -e HF_TOKEN=<your-token>
```

OR mount a config:

``` command
-v ~/.huggingface:/root/.huggingface
```
* Network errors during dataset loading? Make sure Docker Desktop has internet access enabled and isn't firewalled.

---

## 🚀 Usage:
- 🧠 Start an interactive CHARLOTTE session:
    This drops you into the CLI, just like running python core/main.py.
``` command
docker-compose run charlotte
```

- 🧪 Run tests:

``` command
docker-compose run charlotte pytest tests/
```

- 🔁 Rebuild image after code/requirements change:

``` command
docker-compose build
```