FROM python:3.7

ENV INSTALL_PATH /app
RUN mkdir -p $INSTALL_PATH
RUN apt-get update && \
    apt-get install -y netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*

WORKDIR $INSTALL_PATH
RUN mkdir -p /app/app
COPY ./app /app/app
COPY ./ /app
RUN pip install -r requirements.txt
CMD ["/bin/sh", "-c", "python3 /app/run.py"]