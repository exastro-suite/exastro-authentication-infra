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


def curret_user_get():
    """カレントユーザ情報取得

    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL curret_user_get')
        globals.logger.debug('#' * 50)

        # globals.logger.debug('header:{}'.format(request.headers))

        token_user = os.environ["EXASTRO_KEYCLOAK_USER"]
        token_password = os.environ["EXASTRO_KEYCLOAK_PASSWORD"]
        token_realm_name = os.environ["EXASTRO_KEYCLOAK_MASTER_REALM"]

        # realm_nameの取得
        realm_name = api_authc_common.get_current_realm(request.headers)

        # user_idの取得
        user_id = api_authc_common.get_current_user(request.headers)

        # user_idをもとにKeyCloakのuser情報を取得する
        user_info = api_keycloak_call.keycloak_user_get_by_id(realm_name, user_id, token_user, token_password, token_realm_name)

        ret_json = {
            "id": user_id,
            "username": user_info["username"],
            "enabled": user_info["enabled"],
            "firstName": user_info["firstName"],
            "lastName": user_info["lastName"],
            "email": user_info["email"],
        }

        return jsonify({"result": "200", "info": ret_json}), 200

    except Exception as e:
        return common.serverError(e)


def curret_user_password_change():
    """カレントユーザパスワード変更

    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL curret_user_password_change')
        globals.logger.debug('#' * 50)

        token_user = os.environ["EXASTRO_KEYCLOAK_USER"]
        token_password = os.environ["EXASTRO_KEYCLOAK_PASSWORD"]
        token_realm_name = os.environ["EXASTRO_KEYCLOAK_MASTER_REALM"]

        # パラメータ情報(JSON形式)
        payload = request.json.copy()

        cuurent_password = payload["current_password"]
        new_password = payload["password"]

        # globals.logger.debug('in_data:{}'.format(payload))

        # realm nameの取得
        realm_name = api_authc_common.get_current_realm(request.headers)

        # user_idの取得
        user_id = api_authc_common.get_current_user(request.headers)

        # client_nameの取得
        client_name = api_authc_common.get_current_client_name(request.headers)

        # user_idをもとにKeyCloakのuser情報を取得する
        user_info = api_keycloak_call.keycloak_user_get_by_id(realm_name, user_id, token_user, token_password, token_realm_name)

        # client_secretの取得
        client_secret = api_keycloak_call.keycloak_client_secret_get(realm_name, client_name, token_user, token_password, token_realm_name)

        try:
            # 現行パスワードが一致しているかチェック
            token = api_keycloak_call.keycloak_client_user_get_token(realm_name, client_name, client_secret, user_info["username"], cuurent_password)
        except api_keycloak_call.AuthErrorException as e:
            # 認証があった場合は401で戻る
            return jsonify({"result": "401"}), 401

        # パスワード変更
        api_keycloak_call.keycloak_user_reset_password(realm_name, user_id, new_password, token_user, token_password, token_realm_name)

        return jsonify({"result": "200"}), 200

    except Exception as e:
        return common.serverError(e)

def user_client_role_get(user_id, client_id):
    """ユーザークライアントロール取得 user client role get

    Args:
        user_id (str): user id
        client_id (str): client id

    Returns:
        [type]: [description]
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL {}:user_id client_id[{}]'.format(inspect.currentframe().f_code.co_name, user_id, client_id))
        globals.logger.debug('#' * 50)

        ret = {
            "result": "200",
            "rows": [
                {
                    "user_id": user_id,
                    "roles": [
                        {
                            "name": "ws-1-owner",
                            "composite_roles": [
                                {
                                    "name": "ws-1-role-ws-reference",
                                },
                                {
                                    "name": "ws-1-role-ws-name-update",
                                },
                                {
                                    "name": "ws-1-role-ws-ci-update",
                                },
                                {
                                    "name": "ws-1-role-ws-cd-update",
                                },
                                {
                                    "name": "ws-1-role-ws-delete",
                                },
                                {
                                    "name": "ws-1-role-owner-role-setting",
                                },
                                {
                                    "name": "ws-1-role-member-add",
                                },
                                {
                                    "name": "ws-1-role-member-role-update",
                                },
                                {
                                    "name": "ws-1-role-ci-pipeline-result",
                                },
                                {
                                    "name": "ws-1-role-manifest-setting",
                                },
                                {
                                    "name": "ws-1-role-cd-execute",
                                },
                                {
                                    "name": "ws-1-role-cd-execute-result",
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        return jsonify(ret), 200

    except Exception as e:
        return common.serverError(e)

def user_client_role_setting(user_id, client_id):
    """ユーザークライアントロール設定 user client role setting

    Args:
        user_id (str): user id
        client_id (str): client id

    Returns:
        [type]: [description]
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL {}:user_id client_id[{}]'.format(inspect.currentframe().f_code.co_name, user_id, client_id))
        globals.logger.debug('#' * 50)

        # 引数を展開 Expand arguments
        payload = request.json.copy()

        globals.logger.debug(payload)

        roles = []
        # ユーザーに追加するロールを繰り返し処理する Iterate over the roles you add to the user
        for role in payload["roles"]:
            add_role = {
                "name": role["name"]
            }
            roles.append(add_role)

        # realm nameの取得
        realm_name = api_authc_common.get_current_realm(request.headers)

        # user_idの取得
        user_id = api_authc_common.get_current_user(request.headers)

        # client_nameの取得
        client_name = api_authc_common.get_current_client_name(request.headers)

        # user_idをもとにKeyCloakのuser情報を取得する
        user_info = api_keycloak_call.keycloak_user_get_by_id(realm_name, user_id, token_user, token_password, token_realm_name)

        # tokenの取得 get toekn 
        token = api_authc_common.get_current_user_token(request.headers)

        # realm nameの取得
        api_keycloak_call.keycloak_user_client_role_mapping_create(realm_name, user_id, client_id, client_roles, token)

        ret = {
            "result": "200",
        }

        return jsonify(ret), 200

    except Exception as e:
        return common.serverError(e)
