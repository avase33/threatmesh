FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY threatmesh_detector ./threatmesh_detector
RUN pip install --no-cache-dir ".[server]"
ENV THREATMESH_LLM=mock
EXPOSE 8000
CMD ["threatmesh-detector", "serve", "--host", "0.0.0.0", "--port", "8000"]
