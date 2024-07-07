FROM python:3.8

ENV INSTALL_PATH /app
RUN mkdir -p $INSTALL_PATH

WORKDIR $INSTALL_PATH
RUN mkdir -p /app/app
COPY ./app /app/app
COPY ./ /app
RUN pip install -r requirements.txt
EXPOSE 1337
CMD ["/bin/sh", "-c", "python3 /app/run.py"]