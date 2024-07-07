FROM python:3.9-slim
WORKDIR /usr/src/app
COPY main-app/ .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 1337
ENV FLASK_APP=app.py
CMD ["flask", "run", "--host=0.0.0.0", "--port=1337"]