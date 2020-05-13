# api_for_testing

Command to start server and set path to logfile: python api.py -l log_file.txt

Request example `curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f", "method": "online_score", "token": "", "arguments": { "first_name": "stanislav", "last_name": "stupikov", "gender": 1}}'` http://127.0.0.1:8080/method/

Expected Redis database on 'localhost' and port '6379'.

To run unit test : 
`python tests\unit\unit_test.py`

To run untegration test :
`python tests\integration\integration_test.py`

