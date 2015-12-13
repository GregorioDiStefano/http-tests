#Prepare www root to be copied to docker container
tar -zcvf www.tar.gz www

if !(hash docker &>/dev/null); then
    echo "Docker needs to be installed.."
    exit 1
fi

#Build and run
sudo docker build -t http-tests .
sudo docker run -p 7001:7001 -p 7002:7002 -p 7003:7003 -p 7004:7004 -i -t http-tests
