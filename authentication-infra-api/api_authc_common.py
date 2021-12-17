#   Copyright 2021 NEC Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from flask import Flask, request, abort, jsonify, render_template
from datetime import datetime
import inspect
import os
import json
import tempfile
import subprocess
import time
import re
from urllib.parse import urlparse
import base64
import requests
from requests.auth import HTTPBasicAuth
import traceback
from datetime import timedelta, timezone

import yaml
from jinja2 import Template

# User Imports
import globals
import common
import api_keycloak_call
import api_httpd_call

# 設定ファイル読み込み・globals初期化
app = Flask(__name__)
app.config.from_envvar('CONFIG_API_AUTHC_INFRA_PATH')
globals.init(app)


def get_current_user(header):
    """ログインユーザID取得

    Args:
        header (dict): request header情報

    Returns:
        str: ユーザID
    """
    try:
        # 該当の要素が無い場合は、confの設定に誤り
        HEAD_REMOTE_USER = "X-REMOTE-USER"
        if not HEAD_REMOTE_USER in request.headers:
            raise Exception("get_current_user error not found header:{}".format(HEAD_REMOTE_USER))

        remote_user = request.headers[HEAD_REMOTE_USER]
        # globals.logger.debug('{}:{}'.format(HEAD_REMOTE_USER, remote_user))

        # 最初の@があるところまでをuser_idとする
        idx = remote_user.rfind('@')
        user_id = remote_user[:idx]
        # globals.logger.debug('user_id:{}'.format(user_id))

        return user_id

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def get_current_realm(header):
    """ログインユーザのrealm取得

    Args:
        header (dict): request header情報

    Returns:
        str: realm name
    """
    try:
        # 該当の要素が無い場合は、confの設定に誤り
        HEAD_REMOTE_USER = "X-REMOTE-USER"
        if not HEAD_REMOTE_USER in request.headers:
            raise Exception("get_current_realm error not found header:{}".format(HEAD_REMOTE_USER))

        remote_user = request.headers[HEAD_REMOTE_USER]
        # globals.logger.debug('{}:{}'.format(HEAD_REMOTE_USER, remote_user))

        # urlの最後の部分をrealm情報とする
        idx = remote_user.rfind('/')
        realm_name = remote_user[idx+1:]
        # globals.logger.debug('realm_name:{}'.format(realm_name))

        return realm_name

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def get_current_client_name(header):
    """ログインユーザのclient name取得

    Args:
        header (dict): request header情報

    Returns:
        str: client name
    """
    try:
        # 該当の要素が無い場合は、confの設定に誤り
        HEAD_CLIENT_NAME = "OIDC-CLAIM-AUD"
        if not HEAD_CLIENT_NAME in request.headers:
            raise Exception("get_current_client_name error not found header:{}".format(HEAD_CLIENT_NAME))

        client_name = request.headers[HEAD_CLIENT_NAME]
        globals.logger.debug('{}:{}'.format(HEAD_CLIENT_NAME, client_name))

        return client_name

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def get_current_token(header):
    """ログインユーザ token取得

    Args:
        header (dict): request header情報

    Returns:
        str: token
    """
    try:
        # 該当の要素が無い場合は、confの設定に誤り
        HEAD_AUTHORIZATION = "Authorization"
        if not HEAD_AUTHORIZATION in request.headers:
            raise Exception("{} error not found header:{}".format(inspect.currentframe().f_code.co_name, HEAD_REMOTE_USER))

        token = request.headers[HEAD_AUTHORIZATION]
        globals.logger.debug('{}:{}'.format(HEAD_AUTHORIZATION, token))

        return token

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise
