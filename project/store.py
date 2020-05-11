import redis


class Store:

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def retry_10(func):
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < 10:
                try:
                    response = func(*args, **kwargs)
                    return response
                except Exception as e:
                    ex = str(e)
                    attempts += 1
            raise Exception('Error in connection to store')
        return wrapper

    def common_get(self, key, db):
        r = redis.Redis(host=self.host, port=self.port, socket_timeout=10, db=db)
        response = r.get(key)
        if response:
            response = response.decode()
        return response


    #db with 0 index is for score_request, 1 is for interests
    @retry_10
    def cache_get(self, key):
        try:
            response = self.common_get(key, db=0)
        except:
            response = None
        return response


    @retry_10
    def get(self, key):
        response = self.common_get(key, db=1)
        return response


    @retry_10
    def cache_set(self, key, score, time_value):
        try:
            r = redis.Redis(host=self.host, port=self.port, socket_timeout=10, db=0)
            r.set(key, score, time_value)
        except:
            pass
