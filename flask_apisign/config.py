# -*- coding: utf-8 -*-
# @author: songjie
# @email: songjie@shanshu.ai
# @date: 2020/04/06

from flask import current_app


class _Config(object):
    """
    Helper object for accessing and verifying options in this extension. This
    is meant for internal use of the application; modifying config options
    should be done with flasks ```app.config```.

    Default values for the configuration options are set in the jwt_manager
    object. All of these values are read only. This is simply a loose wrapper
    with some helper functionality for flasks `app.config`.
    """

    @property
    def algorithm(self):
        return current_app.config['SIGN_ALGORITHM']

    @property
    def decode_algorithms(self):
        algorithms = current_app.config['SIGN_DECODE_ALGORITHMS']
        if not algorithms:
            return [self.algorithm]
        if self.algorithm not in algorithms:
            algorithms.append(self.algorithm)
        return algorithms

    @property
    def exempt_methods(self):
        return {"OPTIONS"}

    @property
    def sign_location(self):
        return current_app.config.get('SIGN_LOCATION', 'query_string')

    @property
    def timestamp_expiration(self):
        """
        时间戳有效时长，单位秒,默认30秒
        :return:
        """
        return current_app.config.get('SIGN_TIMESTAMP_EXPIRATION', 30)

    @property
    def timestamp(self):
        return current_app.config.get('SIGN_TIMESTAMP_NAME', 'timestamp')

    @property
    def app_id(self):
        return current_app.config.get('SIGN_APP_ID_NAME', 'x-app-id')

    @property
    def signature(self):
        return current_app.config.get('SIGN_SIGNATURE_NAME', 'x-sign')

    @property
    def request_id(self):
        return current_app.config.get('SIGN_REQUEST_ID_NAME', 'x-request-id')

    @property
    def data_key(self):
        return current_app.config.get('SIGN_REQUEST_DATA_NAME', 'x-data')

    @property
    def app_secret(self):
        return current_app.config.get('SIGN_APP_SECRET_NAME', 'app-secret')

    @property
    def access_token(self):
        return current_app.config.get('SIGN_ACCESS_TOKEN_NAME', 'x-access-token')

    @property
    def require_sign(self):
        return current_app.config.get('SIGN_REQUIRE_SIGN', True)

    @property
    def require_token(self):
        return current_app.config.get('SIGN_REQUIRE_TOKEN', False)

    @property
    def error_msg_key(self):
        return current_app.config.get('SIGN_ERROR_MSG_KEY')

    @property
    def app_ids(self):
        return current_app.config.get('SIGN_APP_IDS')

    @property
    def cust_check_app_id_func(self):
        return current_app.config.get('SIGN_CUST_CHECK_APP_ID_FUNC')


config = _Config()
