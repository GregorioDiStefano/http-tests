import unittest
import requests
import os
import random
import hashlib
import socket
import string
import sys
import re
import time

class Helpers(object):
    @staticmethod
    def random_string(minimum=0, maximum=100, printable=False):
        if printable:
            possible_characters = string.ascii_uppercase \
                                  + string.digits \
                                  + string.ascii_lowercase
            rnd_str = ''.join(random.choice(possible_characters) for _ in range(random.randint(minimum, maximum)))
        else:
            rnd_str = os.urandom(random.randint(minimum, maximum))
        return rnd_str

    @staticmethod
    def test_server_from_env():
        try:
            ip = os.environ["TEST_SERVER_IP"]
            port = os.environ["TEST_SERVER_PORT"]
        except KeyError:
            print "Forgot to set TEST_SERVER_IP and TEST_SERVER_PORT enviornment variables?"
            sys.exit(1)
        return ip, port


class RawRequest(object):


    def __init__(self, host, port, method="GET", http_version="1.1", path="/", request=None):
        self.host = host
        self.port = port
        self.method = method
        self.http_version = http_version
        self.path = path
        self.request = request

    def do(self):
        new_line = "\r\n"
        response_seperator = new_line * 2
        status_code = None
        status_line = None

        if not self.request:
            get = "%s %s HTTP/%s" % (self.method, self.path, self.http_version)
            self.request = [
                get,
                "Host: " + self.host,
                "Connection: Close",
                "",
                "",
            ]
            self.request = new_line.join(self.request)

        try:
            s = socket.socket()
            s.connect((self.host, int(self.port)))
            s.send(self.request)

            response = ""
            buf = s.recv(4096*2)
            while buf:
                response += buf
                buf = s.recv(4096*2)
        except Exception:
            return None

        #return entire request, and response
        if response_seperator not in response:
            return {"request": self.request, "response": response}
        else:
            response_headers, response_body = response.split(response_seperator)
            status_line = new_line in response_headers and response_headers.split(new_line)[0]

            if status_line:
                match = re.search("\w*\d{3}\w*", status_line)
            if match:
                status_code = int(match.group(0))

        return {"request": self.request,
                "status_code": status_code,
                "response_headers": response_headers,
                "response_body": response_body}


class Test_Downloads(unittest.TestCase):
    ip, port = Helpers.test_server_from_env()
    host_port = "http://" + ip + ":" + port + "/"
    test_partial_content = False

    def skipIfFalse(flag, msg="Skipped"):
        def deco(f):
            def wrapper(self, *args, **kwargs):
                if not getattr(self, flag):
                    self.skipTest(msg)
                else:
                    f(self, *args, **kwargs)
            return wrapper
        return deco

    @classmethod
    def setUpClass(self):
        try:
            r = requests.head(self.host_port + "download.bin")
            if r.headers.get("Accept-Ranges", "").strip() == "bytes":
                self.test_partial_content = True
        except Exception:
            pass

    def test_download_txt(self):
        r = requests.get(self.host_port + "download.txt", timeout=1)
        dl_sha = hashlib.sha1(r.text).hexdigest()
        self.assertEqual(dl_sha, "22aec3055f5b0380761b52f94f3df8a7c3ab3577", msg="Hash mismatch")

    def test_download_bin(self):
        r = requests.get(self.host_port + "download.bin")
        dl_sha = hashlib.sha1(r.content).hexdigest()
        self.assertEqual(dl_sha, "1d634b64a27f06e63faa705af5b1c720879d531a", msg="Hash mismatch")

    def test_download_bin_0_bytes(self):
        r = requests.get(self.host_port + "download_0_bytes.bin")
        self.assertEqual(r.text, "")

    def test_download_bin_0x00(self):
        r = requests.get(self.host_port + "download-0x00.bin")
        dl_sha = hashlib.sha1(r.content).hexdigest()
        self.assertEqual(dl_sha, "d13ec7927b6274e80beeddf3232193768390dac3", msg="Hash mismatch")

    @skipIfFalse("test_partial_content", "No partial range support")
    def test_partial_range_10_bytes(self):
        headers = {"Range": 'bytes=%s-%s' % (50000, 50009)}
        r = requests.get(self.host_port + "download.bin", headers=headers)
        data = r.content
        dl_sha = hashlib.sha1(data).hexdigest()
        self.assertEqual(dl_sha, "82588b4101fa86741933f4058e56dea9cb5354ba", msg="Hash mismatch, return data length: %d" % len(data))

    #NOTE:  RFC 2616 section 14.35.1
    @skipIfFalse("test_partial_content", "No partial range support")
    def test_partial_range_invalid_characters(self):
        headers = {"Range": 'bytes=%s-%s' % ("asdf;adf;l-af", "fasdfl;asm,x-")}
        r = requests.get(self.host_port + "download.bin", headers=headers)
        self.assertIn(r.status_code, [400, 416])

    @skipIfFalse("test_partial_content", "No partial range support")
    def test_partial_range_last_100_bytes(self):
        headers = {"Range": 'bytes=-%s' % ("100")}
        r = requests.get(self.host_port + "download.bin", headers=headers)
        data = r.content
        dl_sha = hashlib.sha1(data).hexdigest()
        self.assertEqual(dl_sha, "a5d2846bccc25d70e03fe9d94aaa529167b079f2", msg="Hash mismatch, returned data length: %d" % len(data))

    @skipIfFalse("test_partial_content", "No partial range support")
    def test_partial_range_invalid_range(self):
        headers = {"Range": 'bytes=%s-%s' % ("100", "50")}
        r = requests.get(self.host_port + "download.bin", headers=headers)
        self.assertEqual(r.status_code, 416)

    @skipIfFalse("test_partial_content", "No partial range support")
    def test_partial_range__1_bytes(self):
        headers = {"Range": 'bytes=%s-%s' % ("100", "100")}
        r = requests.get(self.host_port + "download.bin", headers=headers)
        data = r.content
        dl_sha = hashlib.sha1(data).hexdigest()
        self.assertEqual(dl_sha, "9b16668f4e16c0e9932661855b7bcb5bad8b0f72", msg="Hash mismach, returned data length: %d" % len(data))

class Test_HTTP_Secuity(unittest.TestCase):
    ip, port = Helpers.test_server_from_env()
    host_port = "http://" + ip + ":" + port + "/"
    test_basic_auth = False

    def skipIfFalse(flag, msg="Skipped"):
        def deco(f):
            def wrapper(self, *args, **kwargs):
                if not getattr(self, flag):
                    self.skipTest(msg)
                else:
                    f(self, *args, **kwargs)
            return wrapper
        return deco

    @classmethod
    def setUpClass(self):
        try:
            r = requests.head(self.host_port + "secret", timeout=1)
            if r.headers.get("WWW-Authenticate", "") == "Basic realm=\"restricted\"":
                self.test_basic_auth = True
        except Exception:
            pass

    def test_path_traversal(self):
        r = requests.get(self.host_port + "../path_traversal.html", timeout=1)
        self.assertNotEqual(r.text.strip(), "Can you see me?", msg="Ouch, path traversal in 2015!")
        self.assertNotEqual(r.status_code, 200)

    def test_path_traversal_percent_encoded(self):
        r = requests.get(self.host_port + "%2e%2e%2fpath_traversal.html", timeout=1)
        self.assertNotEqual(r.text.strip(), "Can you see me?", msg="Ouch, path traversal in 2015!")
        self.assertNotEqual(r.status_code, 200)

    @skipIfFalse("test_basic_auth", "No basic authentication supprt")
    def test_basic_authentication_correct_password(self):
        r = requests.get(self.host_port + "/secret", auth=("greg", "greg"), allow_redirects=True, timeout=1)
        self.assertEqual(r.text.strip(), "Hello again")
        self.assertEqual(r.status_code, 200)

    @skipIfFalse("test_basic_auth", "No basic authentication supprt")
    def test_basic_authentication_incorrect_password(self):
        r = requests.get(self.host_port + "/secret", auth=("greg", "foo"), allow_redirects=True, timeout=1)
        self.assertNotEqual(r.text.strip(), "Hello again")
        self.assertEqual(r.status_code, 401)


class Test_HTTP(unittest.TestCase):
    ip, port = Helpers.test_server_from_env()
    host_port = "http://" + ip + ":" + port + "/"

    def test_get_index(self):
        r = requests.get(self.host_port + "index.html", timeout=1)
        self.assertEqual(r.text.strip(), "Hello World")
        self.assertEqual(r.status_code, 200)

    def test_get_file_in_directory(self):
        r = requests.get(self.host_port + "public/public.html", timeout=1)
        self.assertEqual(r.text.strip(), "Hello from public")
        self.assertEqual(r.status_code, 200)

    def test_get_index_paramters(self):
        r = requests.get(self.host_port + "index.html?x=1111&y=aaaa", timeout=1)
        self.assertEqual(r.text.strip(), "Hello World")
        self.assertEqual(r.status_code, 200)

    def test_get_index_invalid_parameters(self):
        r = requests.get(self.host_port + "index.html?x=1&y=1&bar!#2/", timeout=1)
        self.assertEqual(r.text.strip(), "Hello World")
        self.assertEqual(r.status_code, 200)

    def test_get_file_with_space(self):
        r = requests.get(self.host_port + "foo bar.html", timeout=1)
        self.assertEqual(r.text.strip(), "Hello from Foo Bar")
        self.assertEqual(r.status_code, 200)

    def test_get_file_starts_with_space(self):
        r = requests.get(self.host_port + " whitespace.html", timeout=1)
        self.assertEqual(r.text.strip(), "Hello from Whitespace")
        self.assertEqual(r.status_code, 200)

    def test_get_file_dir_with_space(self):
        r = requests.get(self.host_port + "foo bar/bar.html", timeout=1)
        self.assertEqual(r.text.strip(), "bar")
        self.assertEqual(r.status_code, 200)

    def test_get_index_double_root(self):
        r = requests.get(self.host_port + "//", timeout=1)
        self.assertEqual(r.text.strip(), "Hello World")
        self.assertEqual(r.status_code, 200)

    def test_get_file_not_found_file(self):
        r = requests.get(self.host_port + "filethatdoesntexist.html", timeout=1)
        self.assertEqual(r.status_code, 404)

    def test_get_file_not_found_dir(self):
        r = requests.get(self.host_port + "foo", timeout=1)
        self.assertEqual(r.status_code, 404)

    def test_get_file_not_found_subdir(self):
        r = requests.get(self.host_port + "foo/foo", timeout=1)
        self.assertEqual(r.status_code, 404)

    def test_head_file_not_found_file(self):
        r = requests.head(self.host_port + "filethatdoesntexist.html", timeout=1)
        self.assertEqual(r.status_code, 404)

    def test_head_file_not_found_dir(self):
        r = requests.head(self.host_port + "foo", timeout=1)
        self.assertEqual(r.status_code, 404)

    def test_post_file_not_found_file(self):
        r = requests.post(self.host_port + "filethatdoesntexist.html", {"test": "test"}, timeout=1)
        self.assertIn(r.status_code, [405, 501, 404])

    def test_post_file_not_found_dir(self):
        r = requests.post(self.host_port + "foo", {"test": "test"}, timeout=1)
        self.assertIn(r.status_code, [405, 501, 404])

    def test_forbidden(self):
        r = requests.get(self.host_port + "non_readable.html", timeout=1)
        self.assertIn(r.status_code, [403, 404])

    def test_head(self):
        r = requests.head(self.host_port, timeout=1)
        self.assertEqual(r.text, "", msg="No response body should exist in a HEAD request")
        self.assertEqual(r.status_code, 200)

    #HEAD request on file should return content-length
    def test_head_content_length(self):
        r = requests.head(self.host_port + "download.bin", timeout=1)
        self.assertEqual(r.text, "", msg="No response body should exist in a HEAD request")
        self.assertEqual(r.headers.get("Content-Length", ""), "4732710", msg="Content-Length should be set correctly")
        self.assertEqual(r.status_code, 200)

    #No POST should be permitted on a static page
    def test_post(self):
        r = requests.post(self.host_port + "index.html", {"hi": "this is a test"}, timeout=1)
        self.assertIn(r.status_code, [405, 501])

    #No PUT should be permitted on a static page
    def test_put(self):
        r = requests.put(self.host_port + "index.html", {"hi": "this is a test"}, timeout=1)
        self.assertIn(r.status_code, [405, 501])

    #some http servers simply close the connection
    def test_URI_too_long(self):
        random_long_path = Helpers.random_string(printable=True, minimum=1024*300, maximum=1024*500)
        try:
            r = requests.get(self.host_port + random_long_path)
        except requests.exceptions.ConnectionError:
            pass
        else:
            self.assertEqual(r.status_code, 414)

    def test_send_cookie(self):
        cookies = dict(cookies_are=Helpers.random_string(printable=True, minimum=100, maximum=4000))
        r = requests.get(self.host_port, cookies=cookies, timeout=1)
        self.assertEqual(r.status_code, 200)

    #nginx and some other server just close the connection, this is valid as well.
    def test_send_large_cookie(self):
        cookies = dict(cookies_are=Helpers.random_string(printable=True, minimum=1024*1024, maximum=1024*1024*2))
        r = requests.get(self.host_port, cookies=cookies, timeout=1)
        self.assertEqual(r.status_code, 400)

    def test_utf_8_content(self):
        r = requests.get(self.host_port + "utf8.html", timeout=1)
        sha = hashlib.sha1(r.content).hexdigest()
        self.assertEqual(sha, "e944e24884ef56399864eb04bd20d07a4417aa82", msg="Hash mismatch")

    def test_unsupported_method(self):
        #rr = RawRequest(self.ip, self.port, method="FOO").do()
        req = requests.Request("FOO", self.host_port)
        prepared = req.prepare()
        session = requests.Session()
        resp = session.send(prepared)
        self.assertIn(resp.status_code, [400, 405])

    def test_fuzzer(self):
        for _ in xrange(0, 50):
            rnd_string = Helpers.random_string(printable=False, minimum=1024, maximum=1024*25)
            rr = RawRequest(self.ip, self.port, rnd_string).do()

            #Server does not have to return HTTP request headers
            if rr and rr.get("response", False):
                response = rr["response"].lower()
                if response and "400" not in response and "bad request" not in response:
                    self.fail("Garbage request did not respond with 400 Bad Request")
            elif rr and rr.get("status_code", False):
                if rr["status_code"] != 400:
                    self.fail("Garbage request returned %s and not 400" % rr["status_code"])

    #If we are testing against nginx, check that request limiting is working
    def test_max_request_limit(self):
        check_request = requests.get(self.host_port + "limit/check", timeout=1)
        if check_request.text.strip() != "nginx":
            self.skipTest("request limiting only tested on nginx")

        for _ in range(0, 20):
            requests.get(self.host_port + "limit/")
            time.sleep(.001)
        r = requests.get(self.host_port + "limit/")
        self.assertEqual(r.status_code, 503)
        time.sleep(1)
        r = requests.get(self.host_port + "limit/")
        self.assertEqual(r.status_code, 200)


if __name__ == '__main__':
    test_http = unittest.TestLoader().loadTestsFromTestCase(Test_HTTP)
    unittest.TextTestRunner(verbosity=2).run(test_http)

    test_downloads = unittest.TestLoader().loadTestsFromTestCase(Test_Downloads)
    unittest.TextTestRunner(verbosity=2).run(test_downloads)

    test_security = unittest.TestLoader().loadTestsFromTestCase(Test_HTTP_Secuity)
    unittest.TextTestRunner(verbosity=2).run(test_security)
