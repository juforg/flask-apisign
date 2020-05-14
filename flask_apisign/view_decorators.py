# -*- coding: utf-8 -*-
# @author: songjie
# @email: songjie@shanshu.ai
# @date: 2020/04/05
import datetime
import time
from functools import wraps
from flask import request
from werkzeug.exceptions import BadRequest

from flask_apisign import utils
from flask_apisign.apisign_manager import ApiSign
from flask_apisign.config import config
from flask_apisign.exceptions import NoSignKeyError, InvalidSignError, NoAppIdError, NoRequestIdError, NoSignatureError, NoTimestampError, TimestampFormatterError, \
    RequestExpiredError


def verify_sign(fn):
    """
    A decorator to protect a Flask endpoint.

    If you decorate an endpoint with this, it will ensure that the requester
    has

    See also:
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_sign_in_request()
        return fn(*args, **kwargs)

    return wrapper


def verify_sign_in_request():
    """
        Ensure that the requester has a valid sign.  Raises an appropiate exception there is
        no sign or if the sign is invalid.
        """
    if request.method not in config.exempt_methods:
        api_sign = _get_sign_params_from_request()
        _check_req_timestamp(api_sign.timestamp)
        _check_request_id(api_sign.request_id)
        # if config.require_token:
        #     _check_access_token(api_sign.signature)
        _check_app_id(api_sign.app_id)
        signature = utils.signature(api_sign)
        if signature != api_sign.signature:
            raise InvalidSignError('invalid request signature')


def _get_sign_params_from_request():
    api_sign = None

    # locations = ['query_string', 'headers', 'json', 'form']
    location = config.sign_location
    # add the functions in the order specified in JWT_TOKEN_LOCATION
    if location == 'query_string':
        api_sign = _get_sign_params_from_query_string()
    elif location == 'headers':
        api_sign = _get_sign_params_from_headers()
    elif location == 'json':
        api_sign = _get_sign_params_from_json()
    elif location == 'form':
        api_sign = _get_sign_params_from_form()

    # if config.app_id in api_sign.other_params:
    #     api_sign.other_params.pop(config.app_id)
    # if config.request_id in api_sign.other_params:
    #     api_sign.other_params.pop(config.request_id)
    # if config.signature in api_sign.other_params:
    #     api_sign.other_params.pop(config.signature)
    # if config.timestamp in api_sign.other_params:
    #     api_sign.other_params.pop(config.timestamp)
    # Try to find the param from one of these locations. It only needs to exist
    # in one place to be valid (not every location).

    _check_param_if_exist(api_sign)
    # Do some work to make a helpful and human readable error message if no
    # token was found in any of the expected locations.
    return api_sign


def _check_param_if_exist(api_sign):
    if not api_sign.app_id:
        raise NoAppIdError(f"Missing {config.app_id}")
    if not api_sign.request_id:
        raise NoRequestIdError(f"Missing {config.request_id}")
    if not api_sign.signature:
        raise NoSignatureError(f"Missing {config.signature}")
    if not api_sign.timestamp:
        raise NoTimestampError(f"Missing {config.timestamp}")


def _get_sign_params_from_headers():
    api_sign = ApiSign()
    api_sign.app_id = request.headers.get(config.app_id, None)
    api_sign.request_id = request.headers.get(config.request_id, None)
    api_sign.signature = request.headers.get(config.signature, None)
    api_sign.timestamp = request.headers.get(config.timestamp, None)
    api_sign.other_params = request.headers.get(config.data_key, None)
    if api_sign.other_params is None and request.json is not None:
        api_sign.other_params = request.json.get(config.data_key, None)
    return api_sign


def _get_sign_params_from_query_string():
    api_sign = ApiSign()
    api_sign.app_id = request.args.get(config.app_id, None)
    api_sign.request_id = request.args.get(config.request_id, None)
    api_sign.signature = request.args.get(config.signature, None)
    api_sign.timestamp = request.args.get(config.timestamp, None)
    api_sign.other_params = request.args.get(config.data_key, None)
    if api_sign.other_params is None and request.json is not None:
        api_sign.other_params = request.json.get(config.data_key, None)

    return api_sign


def _get_sign_params_from_json():
    if request.content_type != 'application/json':
        raise NoSignKeyError('Invalid content-type. Must be application/json.')
    try:
        api_sign = ApiSign()
        api_sign.app_id = request.json.get(config.app_id, None)
        api_sign.request_id = request.json.get(config.request_id, None)
        api_sign.signature = request.json.get(config.signature, None)
        api_sign.timestamp = request.json.get(config.timestamp, None)
        if not (api_sign.app_id and api_sign.request_id and api_sign.signature and api_sign.timestamp):
            raise BadRequest()
        api_sign.other_params = request.json.get(config.data_key, None)
    except BadRequest:
        raise NoSignKeyError('Missing "{}" key in json data.')

    # if not auth_header:
    #     raise NoSignKeyError("Missing {} Header".format(header_name))

    return api_sign


def _get_sign_params_from_form():
    if request.content_type != 'application/x-www-form-urlencoded':
        raise NoSignKeyError('Invalid content-type. Must be application/x-www-form-urlencoded.')
    try:
        api_sign = ApiSign()
        api_sign.app_id = request.form.get(config.app_id, None)
        api_sign.request_id = request.form.get(config.request_id, None)
        api_sign.signature = request.form.get(config.signature, None)
        api_sign.timestamp = request.form.get(config.timestamp, None)
        if not (api_sign.app_id and api_sign.request_id and api_sign.signature and api_sign.timestamp):
            raise BadRequest()
        api_sign.other_params = request.form.get(config.data_key, None)
    except BadRequest:
        raise NoSignKeyError('Missing "{}" key in json data.')

    return api_sign


def _check_req_timestamp(req_timestamp):
    """ 校验时间戳
    @pram req_timestamp str,int: 请求参数中的时间戳(10位)
    """
    timestamp = None
    if isinstance(req_timestamp, str) and req_timestamp.isdigit():
        timestamp = int(req_timestamp)
    else:
        raise TimestampFormatterError(req_timestamp)
    if len(str(timestamp)) == 13:
        timestamp = int(timestamp / 1000)
    if len(str(timestamp)) == 10:
        now_timestamp = int(time.mktime(datetime.datetime.now().timetuple()))
        if timestamp <= now_timestamp <= timestamp + config.timestamp_expiration:
            return True
        else:
            raise RequestExpiredError(f"request_timestamp:{timestamp},now_timestamp:{now_timestamp},configed_expiration:{config.timestamp_expiration}")
    else:
        raise TimestampFormatterError(timestamp)


def _check_request_id(request_id):
    """
    校验 request id ,是否已经使用过了
    :param request_id:
    :return:
    """
    # todo
    pass


def _check_access_token(access_token):
    """
    校验 access_token id ,是否合法
    :param access_token:
    :return:
    """
    # todo
    pass


def _check_app_id(app_id):
    """
    校验 app_id ,是否合法
    :param app_id:
    :return:
    """
    # todo 调用自己实现的类 或者从配置里取配置看看 app_id 是否合法
    pass

