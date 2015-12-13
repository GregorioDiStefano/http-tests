# test-http
Automated tests for the HTTP protocol

Instructions:
  1. Install Docker for your distro
  2. `bash run.sh`
  3. `TEST_SERVER_IP=127.0.0.1 TEST_SERVER_PORT=<port> python tests.py`

Port 7001 is running [simple-http-server](https://github.com/andrewpthorp/simple-http-server)

Port 7002 is running [nginx](https://nginx.com)

Port 7003 is running [webfs](http://linux.bytesex.org/misc/webfs.html)

Port 7004 is running [http-server](https://github.com/indexzero/http-server)
