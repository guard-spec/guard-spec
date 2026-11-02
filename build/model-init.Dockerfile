# syntax=docker/dockerfile:1
# model-init: downloads HuggingFace models and exports to ONNX

FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    transformers==4.46.0 \
    "optimum[onnxruntime]==1.23.3" \
    torch==2.4.1+cpu \
    --extra-index-url https://download.pytorch.org/whl/cpu

COPY cmd/model-init/download.py .

VOLUME ["/models"]
ENTRYPOINT ["python", "download.py"]
CMD ["--help"]
