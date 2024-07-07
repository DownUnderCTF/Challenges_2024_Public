FROM python:3.12.4-slim-bullseye

COPY ./requirements.txt /bot/requirements.txt
RUN pip3 install -r /bot/requirements.txt

COPY . /bot
RUN /usr/sbin/useradd --no-create-home www-bot
USER www-bot
WORKDIR /bot

CMD ["python3", "/bot/main.py"]