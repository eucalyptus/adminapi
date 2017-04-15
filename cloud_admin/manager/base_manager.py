
from flask import Flask, jsonify, abort, request
from werkzeug.exceptions import BadRequest
from datetime import datetime, timedelta
from cloud_utils.log_utils import format_log_level
from cloud_utils.system_utils.processutils import local_cmd
import json


def json_serial(obj):
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    if isinstance(obj, timedelta):
        return obj.total_seconds()
    raise TypeError ("Type not serializable:{0}/{1}".format(type(obj), obj))

class BaseManager(object):

    def __init__(self, name=None, version=None, log_level='debug', *args, **kwargs):
        self.version = version or 0.0
        self.name = name or self.__class__.__name__
        self.app = Flask(import_name=self.name)
        self.logger = self.app.logger
        self.logger.setLevel(format_log_level(log_level))
        self._config = {}
        self.load_url_rules()
        self.state = 'alive'

    def load_url_rules(self):
        self.app.add_url_rule('/status/<status_attr>', None, self.get_status, methods=['GET'])
        self.app.add_url_rule('/status', None, self.get_status, strict_slashes=False,
                              methods=['GET'])
        self.app.add_url_rule('/config', None, self.get_config, strict_slashes=False,
                              methods=['GET'])
        self.app.add_url_rule('/config/<path:config_path>', None, self.get_config, methods=['GET'])
        self.app.add_url_rule('/', None, self.get_api, methods=['GET'])
        self.app.add_url_rule('/loglevel', None, self.set_log_level, strict_slashes=False,
                              methods=['GET', 'PUT'])
        self.app.add_url_rule('/execute', None, self.execute, strict_slashes=False,
                              methods=['GET', 'PUT'])


    def __repr__(self):
        return str(self.name)
    @property
    def config(self):
        return {'flask': dict(self.app.config),
                str(self.name).lower(): self._config}

    @property
    def status(self):
        return {'state': getattr(self, 'state', 'starting'),
                'name': self.name, 'version':self.version}

    def get_config(self, config_path=None):
        current_config = self.config
        if config_path:
            paths = str(config_path).split('/')
            for path in paths:
                if str(path) not in current_config:
                    self.logger.error('Could not find path in config:{0}'.format(path))
                    abort(404)
                current_config = current_config.get(path)
        current_config = json.loads(json.dumps(current_config, default=json_serial))
        return jsonify(current_config)

    def get_status(self, status_attr=None):
        status = self.status
        if status_attr:
            if status_attr not in status:
                print 'doh...'
                self.logger.error('Could not find status attribute:{0}'.format(status_attr))
                abort(404)
            else:
                return jsonify(status.get(status_attr))
        return jsonify(status)

    def set_log_level(self):
        if request.method == 'PUT':
            try:
                j = request.get_json(force=True)
            except BadRequest as BE:
                self.logger.error('Error:"{0}"'.format(BE))
                BE.description += ' Is the json formatted correctly in the request?'
                raise BE
            if not j or not 'log_level' in j:
                self.logger.error('"log_level" not present in request.json:"{0}"'
                                  .format(j))
                abort(400, '"log_level" not present in request.json"')
            try:
                level = format_log_level(j['log_level'], default=None)
                self.logger.setLevel(level)
            except Exception as E:
                self.logger.error(E)
                abort(500, str(E))
        return jsonify({'log_level': self.logger.level}), 201

    def get_api(self):
        return jsonify({'api': [str(x) for x in self.app.url_map.iter_rules()]})

    def add_url_rul(self, *args, **kwargs):
        return self.app.add_url_rule(*args, **kwargs)

    def update_config(self):
        raise NotImplementedError()

    def execute(self):
        res = {'run_error': 'Command not run'}
        try:
            j = request.get_json(force=True)
        except BadRequest as BE:
            self.logger.error('Error:"{0}"'.format(BE))
            BE.description += ' Is the json formatted correctly in the request?'
            raise BE
        if not j or 'command' not in j:
            self.logger.error('"command" not present in request.json:"{0}"'
                              .format(j))
            abort(400, '"command" not present in request.json"')
        try:
            kwargs = {}
            kwargs['cmd'] = j['command']
            timeout = j.get('timeout', None)
            if timeout is not None:
                kwargs['timeout'] = timeout
            kwargs['inactivity_timeout'] = j.get('inactivity_timeout', None)
            kwargs['shell'] = self.format_bool(j.get('shell', False))
            kwargs['verbose'] = self.format_bool(j.get('verbose', True))
            res = local_cmd(**kwargs) or {}
            if 'process' in res:
                res.pop('process')
            timeout_error = res.get('timeout_error', None)
            if timeout_error:
                res['timeout_error'] = str(timeout_error)
        except Exception as E:
            self.logger.error(E)
            abort(500, str(E))
        return jsonify(res)

    def test(self):
        return jsonify({'test worked': True})


    def format_bool(self, value):
        if value in [True, 'true', 'True']:
            return  True
        else:
            return False



if __name__ == '__main__':
    manager = BaseManager()
    manager.app.run(debug=True)

