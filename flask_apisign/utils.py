# -*- coding: utf-8 -*-
# @author: songjie
# @email: songjie@shanshu.ai
# @date: 2020/04/06
from flask import current_app
import hashlib

from flask_apisign.apisign_manager import ApiSign
import base64


def _md5(pwd):
    return hashlib.md5(pwd).hexdigest()


def _get_apisign_manager():
    try:
        return current_app.extensions['flask-apisign']
    except KeyError:  # pragma: no cover
        raise RuntimeError("You must initialize a ApiSignManager with this flask "
                           "application before using this method")


def signature(api_sign: ApiSign):
    apisign_manager = _get_apisign_manager()
    sorted_params = sorted(api_sign.dict().items(), key=lambda param_list: param_list[0])
    query_str = ''
    for (k, v) in sorted_params:
        query_str += f"{k}={v}&"
    query_str += apisign_manager.get_and_check_app_secret(api_sign.app_id)
    sign = _md5(query_str.encode('utf-8')).upper()
    return sign


def base64url_decode(input_str):
    return base64.urlsafe_b64decode(input_str)


def base64url_encode(input_str):
    return base64.urlsafe_b64encode(input_str).replace(b'=', b'')