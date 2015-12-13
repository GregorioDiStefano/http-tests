RED='\033[0;31m'
NC='\033[0m'

echo -e "${RED}nserver is running on localhost:7001\nNGINX is running on localhost:7002\nwebfs is running on localhost:7003\nsimple-http-server is running on localhost:7004${NC}"

chmod 0000 /www/main/non_readable.html
nserver -d /www/main -p 7001 &
webfsd -4 -p 7003 -R /www/main/ -f index.html &
http-server /www/main/ -i -d -p 7004 &
nginx
