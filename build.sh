docker stop $(docker ps -aq)
docker rm $(docker ps -aq)


docker network create plain-net1
docker network create plain-net2
docker network create enc-net

docker create --name server1 -it ubuntu
docker network connect plain-net1 server1
docker start server1

docker build -t mazpin1 .

docker build -t mazpin2 .

docker create --name server2 -it ubuntu
docker network connect plain-net2 server2
docker start server2


docker run -d -it -e ENCRYPTED_IP=mazpin2 -e PLAIN_IP=server1 --name mazpin1 mazpin1
docker run -d -it -e ENCRYPTED_IP=mazpin1 -e PLAIN_IP=server2 --name mazpin2 mazpin2
docker network connect plain-net1 mazpin1
docker network connect enc-net mazpin1
docker network connect plain-net2 mazpin2
docker network connect enc-net mazpin2
