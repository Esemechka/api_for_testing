import unittest
import sys
import datetime
import hashlib
import requests
from http.server import HTTPServer
import threading
from unittest.mock import patch
import ast
sys.path.append('project/')
import api


class IntegrationTestSuit(unittest.TestCase):
    def setUp(self):
        self.host = 'localhost'
        self.port = 6379
        self.server = HTTPServer(("localhost", 8080), api.MainHTTPHandler)
        self.headers = {'Content-Type': 'application/json'}
        self.url = 'http://127.0.0.1:8080/method/'
        threading.Thread(target=self.serve).start()

    def serve(self):
        try:
            self.server.serve_forever()
        finally:
            self.server.server_close()

    def set_valid_auth(self, request):
        if request.get("login") == api.ADMIN_LOGIN:
            msg = (datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode('utf-8')
            request["token"] = hashlib.sha512(msg).hexdigest()
        else:
            msg = str(request.get("account", "")) + str(request.get("login", "")) + api.SALT
            request["token"] = hashlib.sha512(msg.encode('utf-8')).hexdigest()

    @patch('store.Store.cache_get')
    def test_scoring_all_filelds_filled(self, mock_cache_get):
        mock_cache_get.return_value = None
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score",
                   "arguments": {"phone": "79175002040", "email": "stupnikov@mail.ru", "gender": 1,
                                 "birthday": "01.01.2015", "first_name": "a", "last_name": "b"}}
        self.set_valid_auth(request)
        r = requests.post(headers=self.headers, url=self.url, json=request)
        response = ast.literal_eval(r.text)['response']
        self.assertEqual(5, response["score"], request)

    @patch('store.Store.get')
    def test_no_interest(self, mock_get):
        mock_get.return_value = None
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
                   "arguments": {"client_ids": [1, 2, 3], "date": "19.07.2017"}}
        ids =[i for i in request["arguments"]["client_ids"]]
        dict_you_want = {str(your_key): f'no data about client {your_key}' for your_key in ids}
        self.set_valid_auth(request)
        r = requests.post(headers=self.headers, url=self.url, json=request)
        dict_you_get = ast.literal_eval(r.text)['response']
        self.assertEqual(dict_you_want, dict_you_get, request)

    @patch('store.Store.get')
    def test_error_in_db_interest(self, mock_get):
        mock_get.side_effect = Exception()

        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
                   "arguments": {"client_ids": [1, 2, 3], "date": "19.07.2017"}}
        self.set_valid_auth(request)
        r = requests.post(headers=self.headers, url=self.url, json=request)
        dict_you_get = ast.literal_eval(r.text)['error']
        self.assertEqual("Error in connection to store", dict_you_get, request)

    def tearDown(self):
        self.server.shutdown()


if __name__ == "__main__":
    unittest.main()