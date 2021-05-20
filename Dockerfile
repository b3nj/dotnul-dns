FROM python:3.8-alpine
RUN mkdir /app
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
WORKDIR /app
ADD requirements.txt /app
ADD main.py /app
RUN pip3 install -r requirements.txt
CMD ["gunicorn", "-w 4" , "-b", "0.0.0.0:8000", "main:app"]