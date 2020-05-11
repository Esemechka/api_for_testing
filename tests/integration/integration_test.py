import unittest
import api
import datetime
import hashlib
import redis
import requests
from http.server import HTTPServer
from api import MainHTTPHandler
import ast
import logging
import threading


class IntegrationTestSuit(unittest.TestCase):
    def setUp(self):
        self.host = 'localhost'
        self.port = 6379
        self.server = HTTPServer(("localhost", 8080), MainHTTPHandler)
        threading.Thread(target=self.server.serve_forever).start()
        self.headers = {'Content-Type': 'application/json'}
        self.url = 'http://127.0.0.1:8080/method/'

    def set_valid_auth(self, request):
        if request.get("login") == api.ADMIN_LOGIN:
            msg = (datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode('utf-8')
            request["token"] = hashlib.sha512(msg).hexdigest()
        else:
            msg = str(request.get("account", "")) + str(request.get("login", "")) + api.SALT
            request["token"] = hashlib.sha512(msg.encode('utf-8')).hexdigest()

    def initialize_db_v_data(self, dict_k_v, db):
        r = redis.Redis(host=self.host, port=self.port, db=db)
        for k, v in dict_k_v:
            r.set(k, v)

    def clear_db(self, db):
        logging.info(f'clear_db starts')
        r = redis.Redis(host=self.host, port=self.port, db=db)
        for key in r.scan_iter("*"):
            r.delete(key)
        logging.info(f'db is clear')

    def test_get_interest(self):
        self.clear_db(1)
        dict_k_v_sample = {'i:1': 'Nothing', 'i:2': 'Food'}
        self.initialize_db_v_data(dict_k_v=dict_k_v_sample.items(), db=1)
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
                   "arguments": {"client_ids": [1, 2], "date": "19.07.2017"}}
        ids =[i for i in request["arguments"]["client_ids"]]
        dict_you_want = {str(your_key): dict_k_v_sample["i:%s" % your_key] for your_key in ids}
        self.set_valid_auth(request)
        r = requests.post(headers=self.headers, url=self.url, json=request)
        dict_you_get = ast.literal_eval(r.text)['response']
        self.assertEqual(dict_you_want, dict_you_get, request)

    def test_no_interest(self):
        self.clear_db(1)
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
                   "arguments": {"client_ids": [1, 2, 3], "date": "19.07.2017"}}
        ids =[i for i in request["arguments"]["client_ids"]]
        dict_you_want = {str(your_key): f'no data about client {your_key}' for your_key in ids}
        self.set_valid_auth(request)
        r = requests.post(headers=self.headers, url=self.url, json=request)
        dict_you_get = ast.literal_eval(r.text)['response']
        self.assertEqual(dict_you_want, dict_you_get, request)

    def test_scoring_all_filelds_filled(self):
        self.clear_db(0)
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score",
                   "arguments": {"phone": "79175002040", "email": "stupnikov@mail.ru", "gender": 1,
                                 "birthday": "01.01.2015", "first_name": "a", "last_name": "b"}}
        self.set_valid_auth(request)
        r = requests.post(headers=self.headers, url=self.url, json=request)
        response = ast.literal_eval(r.text)['response']
        self.assertEqual(5, response["score"], request)

    def tearDown(self):
        self.server.shutdown()


if __name__ == "__main__":
    unittest.main()