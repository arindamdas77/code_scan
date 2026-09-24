FROM python:3.12-slim
RUN useradd --uid 10002 --create-home sandbox
USER 10002:10002
WORKDIR /workspace
CMD ["python", "-c", "print('Sandbox ready; repository code is not executed automatically.')"]
