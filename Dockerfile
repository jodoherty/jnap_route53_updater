FROM ubuntu

RUN apt-get -y update && apt-get -y install python3 python3-boto3

ADD update_dns.py /update_dns.py

RUN chmod 755 /update_dns.py

ENTRYPOINT ["python3.6", "-u", "/update_dns.py"]
