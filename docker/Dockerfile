FROM ubuntu

RUN apt update -y 
RUN yes | apt install -y tshark  
RUN apt install -y python3-pip
RUN pip3 install scapy
RUN apt install -y python3
RUN apt-get install -y net-tools
RUN apt-get install -y iputils-ping

#WORKDIR /Mazpin

COPY . .

CMD ["python3", "./main.py"]
