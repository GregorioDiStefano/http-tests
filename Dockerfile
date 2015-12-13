FROM ubuntu:latest

RUN \
    apt-get update && \
    apt-get install -y nodejs-legacy npm

RUN \
    apt-get update && \
    apt-get install -y wget

RUN \
    apt-get update && \
    apt-get install -y nginx && \
    rm -rf /var/lib/apt/lists/* && \
    echo "\ndaemon off;" >> /etc/nginx/nginx.conf && \
    chown -R www-data:www-data /var/lib/nginx

#Copy and configure www root
ADD www.tar.gz /
CMD cd / && tar -xvf www.tar.gz && cd -
CMD chmod 0000 /www/non_readable.html

#Configure nginx
VOLUME ["/www", /etc/nginx/sites-enabled", "/etc/nginx/certs", "/etc/nginx/conf.d", "/var/log/nginx", "/var/www/html"]
ADD conf/nginx/default /etc/nginx/sites-enabled/default

#Install, configure webfs
WORKDIR /var/tmp
RUN wget "https://www.kraxel.org/releases/webfs/webfs-1.21.tar.gz"
RUN tar xvf webfs-1.21.tar.gz && cd webfs-1.21/ &&  make && make install

#Install nserver (nodejs)
RUN npm install -g simple-http-server

#Install, configure http-server (nodejs)
RUN npm install http-server -g

ADD conf/start-servers.sh .
CMD bash start-servers.sh



# Expose ports.
EXPOSE 7001
EXPOSE 7002
EXPOSE 7003
EXPOSE 7004
