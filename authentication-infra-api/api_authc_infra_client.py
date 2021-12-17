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
import api_authc_common
import api_keycloak_call
import api_httpd_call

# 設定ファイル読み込み・globals初期化
app = Flask(__name__)
app.config.from_envvar('CONFIG_API_AUTHC_INFRA_PATH')
globals.init(app)


def get_client_port(client_id):
    """client port情報取得

    Args:
        client_id (str): client id

    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL get_client_port')
        globals.logger.debug('#' * 50)

        token_user = os.environ["EXASTRO_KEYCLOAK_USER"]
        token_password = os.environ["EXASTRO_KEYCLOAK_PASSWORD"]
        token_realm_name = os.environ["EXASTRO_KEYCLOAK_MASTER_REALM"]

        # realm nameの取得
        realm_name = api_authc_common.get_current_realm(request.headers)

        # client情報取得
        response = api_keycloak_call.keycloak_client_get(realm_name, client_id, token_user, token_password, token_realm_name)
        json_ret = json.loads(response)

        if "error" in json_ret:
            # client情報取得で"error"のレスポンスが返ってきた場合は、404:NotFound のエラーを返す
            return jsonify(json_ret), 404

        ret = {
            "result": "200",
            "baseUrl": json_ret["baseUrl"],
            "enabled": True,
        }

        return jsonify(ret), 200

    except Exception as e:
        return common.serverError(e)


def client_role_setting(realm, client_id):
    """クライアントロール設定 client role setting

    Args:
        realm (str): realm
        client_id (str): client id

    Returns:
        [type]: [description]
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL {}: realm[{}] client_id[{}]'.format(inspect.currentframe().f_code.co_name, realm, client_id))
        globals.logger.debug('#' * 50)

        ret = {
            "result": "200",
        }

        return jsonify(ret), 200

    except Exception as e:
        return common.serverError(e)
