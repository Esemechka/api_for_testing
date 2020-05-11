import hashlib
import datetime
import unittest
import sys
import functools
sys.path.append('project/')
from store import Store
import api


def cases(cases):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args):
            for c in cases:
                new_args = args + (c if isinstance(c, tuple) else (c,))
                try:
                    f(*new_args)
                except AssertionError as e:
                    print(f"Fault case is {new_args[1]}")
                    raise e

        return wrapper

    return decorator


class TestSuite(unittest.TestCase):
    def setUp(self):
        self.context = {}
        self.headers = {}
        self.settings = Store(host='localhost', port=6379)

    def get_response(self, request):
        return api.method_handler({"body": request, "headers": self.headers}, self.context, self.settings)

    def set_valid_auth(self, request):
        if request.get("login") == api.ADMIN_LOGIN:
            msg = (datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode('utf-8')
            request["token"] = hashlib.sha512(msg).hexdigest()
        else:
            msg = str(request.get("account", "")) + str(request.get("login", "")) + api.SALT
            request["token"] = hashlib.sha512(msg.encode('utf-8')).hexdigest()

    def test_empty_request(self):
        _, code = self.get_response({})
        self.assertEqual(api.INVALID_REQUEST, code)

    @cases([
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": {}},
        {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "sdd", "arguments": {}},
        {"account": "horns&hoofs", "login": "admin", "method": "online_score", "token": "", "arguments": {}}
    ])
    def test_bad_auth(self, request):
        _, code = self.get_response(request)
        self.assertEqual(api.FORBIDDEN, code)


    ok_query = {"phone": "79175002040", "email": "stupnikov@mail.ru", "gender": 1, "birthday": "01.01.2015"}
    @cases([
        {"account": 1, "login": "h&f", "method": "online_score", "arguments": ok_query},
        {"account":  "horns&hoofs", "login": 1, "method": "online_score", "arguments": ok_query},
        {"account":  "horns&hoofs", "login": "h&f", "arguments": {"phone": "79175002040",
        "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
         "first_name": "s", "last_name": 2}},
        {"account":  "horns&hoofs", "login": "h&f", "arguments": {"phone": "79175002040",
        "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000", "first_name": 1}},
        {"account":  "horns&hoofs", "login": "h&f", "arguments": {"email": "stupnikov@otus.ru",
        "gender": 1, "last_name": 2}}
    ])
    def test_charfield(self, request):
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)
        self.assertTrue(len(response))

    ok_query = {"phone": "79175002040", "email": "stupnikov@mail.ru", "gender": 1, "birthday": "01.01.2015"}

    @cases([
        {"account": "horns&hoofs", "method": "online_score", "arguments": ok_query},
        {"account":  "horns&hoofs", "login": "h&f", "method": "online_score"},
        {"account":  "horns&hoofs", "login": "h&f", "arguments": ok_query}
    ])
    def test_requiredfield(self, request):
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)
        self.assertTrue(len(response))

    @cases([
        {"phone": "79175002040", "email": "stupnikov", "gender": 1, "birthday": "01.01.2015"},
        {"phone": "79175002040", "email": 1, "gender": 1, "birthday": "01.01.2015"}
    ])
    def test_bad_email(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)
        self.assertTrue(len(response))

    @cases([
        {"phone": "phone", "email": "stupnikov@mail.ru", "gender": 1, "birthday": "01.01.2015"},
        {"phone": 111, "email": "stupnikov@mail.ru", "gender": 1, "birthday": "01.01.2015"},
        {"phone": "89175002040", "email": "stupnikov@otus.ru"},

    ])
    def test_bad_phone(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)
        self.assertTrue(len(response))

    @cases([
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.1890"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "XXX"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01-01-2000"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "2000.01.01"}
    ])
    def test_bad_birthday(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)
        self.assertTrue(len(response))

    @cases([
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": "1"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": -1},

    ])
    def test_gender(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code)
        self.assertTrue(len(response))

    @cases([
        {},
        {"phone": "79175002040"},
        {"phone": "79175002040", "email": "stupnikovotus.ru", "gender": "1"},
        {"phone": "79175002040", "birthday": "01.01.2000", "first_name": "s"}
    ])
    def test_not_enough_data_in_score_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, arguments)
        self.assertTrue(len(response))

    @cases([
        {"phone": "79175002040", "email": "stupnikov@otus.ru"},
        {"phone": 79175002040, "email": "stupnikov@otus.ru"},
        {"gender": 1, "birthday": "01.01.2000", "first_name": "a", "last_name": "b"},
        {"gender": 0, "birthday": "01.01.2000"},
        {"gender": 2, "birthday": "01.01.2000"},
        {"first_name": "a", "last_name": "b"},
        {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
         "first_name": "a", "last_name": "b"},
    ])
    def test_ok_score_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code)
        score = response.get("score")
        self.assertTrue(isinstance(score, (int, float)) and score >= 0, arguments)
        self.assertEqual(sorted(self.context["has"]), sorted(arguments.keys()))

    @cases([{"phone": "79175002040", "email": "stupnikov@otus.ru"}])
    def test_ok_score_admin_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "admin", "method": "online_score", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code)
        score = response.get("score")
        self.assertEqual(score, 42)

    @cases([
        {},
        {"date": "20.07.2017"},
        {"client_ids": [1, 2], "date": "XXX"},
    ])
    def test_invalid_interests_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, arguments)
        self.assertTrue(len(response))

    @cases([
        {"client_ids": [], "date": "20.07.2017"},
        {"client_ids": {1: 2}, "date": "20.07.2017"},
        {"client_ids": ["1", "2"], "date": "20.07.2017"}
    ])
    def test_bad_client_ids_field(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, arguments)
        self.assertTrue(len(response))

    @cases([
        {"client_ids": [1, 2, 3], "date": datetime.datetime.today().strftime("%d.%m.%Y")},
        {"client_ids": [1, 2], "date": "19.07.2017"},
        {"client_ids": [0]},
    ])
    def test_ok_interests_request(self, arguments):
        request = {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": arguments}
        self.set_valid_auth(request)
        response, code = self.get_response(request)
        self.assertEqual(api.OK, code, request)
        self.assertEqual(len(arguments["client_ids"]), len(response))
        self.assertEqual(self.context.get("nclients"), len(arguments["client_ids"]))


if __name__ == "__main__":
    unittest.main()
