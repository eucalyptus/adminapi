### Example using ipython and the test client...

```
In [38]: from cloud_admin.manager.base_manager import BaseManager

In [39]: bm = BaseManager()

In [40]: t = bm.app.test_client()

In [41]: print t.get('/').get_data()
{
  "api": [
    "/loglevel", 
    "/execute", 
    "/status", 
    "/config", 
    "/", 
    "/status/<status_attr>", 
    "/static/<path:filename>", 
    "/config/<path:config_path>"
  ]
}


In [42]: print t.get('/status').get_data()
{
  "name": "BaseManager", 
  "state": "alive", 
  "version": 0.0
}


In [47]: print t.put('/execute', data='{"command": "ls -la", "verbose": true, "timeout": 10}').get_data()
(73226):euca-core-10-1-1-23.eucalyptus-systems.com#: ls -la
(73226): total 40
(73226): drwxr-xr-x+  6 user  staff   204 Apr 17 08:31 .
(73226): drwxr-xr-x+ 14 user  staff   476 Apr  6 14:54 ..
(73226): -rw-r--r--+  1 user  staff     0 Jun 15  2015 __init__.py
(73226): -rw-r--r--+  1 user  staff  5887 Apr 14 20:08 base_manager.py
(73226): -rw-r--r--+  1 user  staff  5048 Apr  7 16:43 base_manager.pyc
(73226): -rw-r--r--+  1 user  staff   150 Apr 18 13:42 garbage

(73226) Monitor subprocess io finished

{
  "cb_result": null, 
  "cmd": "ls -la", 
  "elapsed": 0.013487100601196289, 
  "inactivity_timeout": 10, 
  "io_bytes": 391, 
  "pid": 73226, 
  "run_error": null, 
  "rx_bytes": 0, 
  "status": 0, 
  "stderr": [], 
  "stdout": [
    "total 40", 
    "drwxr-xr-x+  6 user  staff   204 Apr 17 08:31 .", 
    "drwxr-xr-x+ 14 user  staff   476 Apr  6 14:54 ..", 
    "-rw-r--r--+  1 user  staff     0 Jun 15  2015 __init__.py", 
    "-rw-r--r--+  1 user  staff  5887 Apr 14 20:08 base_manager.py", 
    "-rw-r--r--+  1 user  staff  5048 Apr  7 16:43 base_manager.pyc", 
    "-rw-r--r--+  1 user  staff   150 Apr 18 13:42 garbage"
  ], 
  "timeout": 10, 
  "timeout_error": null
}

```

### Example running standalone and using curl...

```
prompt#> python base_manager.py


prompt#> curl http://127.0.0.1:5000/config/
{
  "basemanager": {}, 
  "flask": {
    "APPLICATION_ROOT": null, 
    "DEBUG": true, 
    "EXPLAIN_TEMPLATE_LOADING": false, 
    "JSONIFY_MIMETYPE": "application/json", 
    "JSONIFY_PRETTYPRINT_REGULAR": true, 
    "JSON_AS_ASCII": true, 
    "JSON_SORT_KEYS": true, 
    "LOGGER_HANDLER_POLICY": "always", 
    "LOGGER_NAME": "BaseManager", 
    "MAX_CONTENT_LENGTH": null, 
    "PERMANENT_SESSION_LIFETIME": 2678400.0, 
    "PREFERRED_URL_SCHEME": "http", 
    "PRESERVE_CONTEXT_ON_EXCEPTION": null, 
    "PROPAGATE_EXCEPTIONS": null, 
    "SECRET_KEY": null, 
    "SEND_FILE_MAX_AGE_DEFAULT": 43200.0, 
    "SERVER_NAME": null, 
    "SESSION_COOKIE_DOMAIN": null, 
    "SESSION_COOKIE_HTTPONLY": true, 
    "SESSION_COOKIE_NAME": "session", 
    "SESSION_COOKIE_PATH": null, 
    "SESSION_COOKIE_SECURE": false, 
    "SESSION_REFRESH_EACH_REQUEST": true, 
    "TEMPLATES_AUTO_RELOAD": null, 
    "TESTING": false, 
    "TRAP_BAD_REQUEST_ERRORS": false, 
    "TRAP_HTTP_EXCEPTIONS": false, 
    "USE_X_SENDFILE": false
  }
}

prompt#> curl -i -H "Content-Type: application/json" -X PUT -d '{"command": "ls -la", "verbose": "True", "timeout":10}' http://localhost:5000/execute
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 800
Server: Werkzeug/0.11.15 Python/2.7.10
Date: Tue, 25 Apr 2017 21:51:05 GMT

{
  "cb_result": null, 
  "cmd": "ls -la", 
  "elapsed": 0.010369062423706055, 
  "inactivity_timeout": 10, 
  "io_bytes": 455, 
  "pid": 73298, 
  "run_error": null, 
  "rx_bytes": 0, 
  "status": 0, 
  "stderr": [], 
  "stdout": [
    "total 48", 
    "drwxr-xr-x+  7 user  staff   238 Apr 25 14:50 .", 
    "drwxr-xr-x+ 14 user  staff   476 Apr  6 14:54 ..", 
    "-rw-r--r--+  1 user  staff  1928 Apr 25 14:50 README.md", 
    "-rw-r--r--+  1 user  staff     0 Jun 15  2015 __init__.py", 
    "-rw-r--r--+  1 user  staff  5887 Apr 14 20:08 base_manager.py", 
    "-rw-r--r--+  1 user  staff  5048 Apr  7 16:43 base_manager.pyc", 
    "-rw-r--r--+  1 user  staff   150 Apr 18 13:42 garbage"
  ], 
  "timeout": 10, 
  "timeout_error": null
}

```