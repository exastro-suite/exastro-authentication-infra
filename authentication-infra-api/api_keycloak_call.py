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
import inspect
import os
import json
import subprocess
import time
import requests
import traceback

from urllib.parse import urlparse

from datetime import datetime
from datetime import timedelta, timezone

import globals

class AuthErrorException(Exception):
    pass

# 設定ファイル読み込み・globals初期化
app = Flask(__name__)
app.config.from_envvar('CONFIG_API_AUTHC_INFRA_PATH')
globals.init(app)

def keycloak_realm_create(realm_name, realm_opt, token_user, token_password, token_realm_name):
    """realm作成

    Args:
        realm_name (str): realm name
        realm_opt (dict): パラメータのオプション値(json)
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name

    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_realm_create: realm_name:{}'.format(realm_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        data_para = {
            "realm": realm_name,
        }

        # その他のオプション値はすべてそのまま受け渡す
        if realm_opt is not None:
            for key in realm_opt.keys():
                data_para[key] = realm_opt[key]

        globals.logger.debug("realms post送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        globals.logger.debug(data_para)

        request_response = requests.post("{}/auth/admin/realms".format(api_url), headers=header_para, data=json.dumps(data_para))

        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 201:
            raise Exception("realm_create error status:{}, response:{}".format(request_response.status_code, request_response.text))

        globals.logger.debug("realm create Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_realm_role_create(realm_name, realm_role_name, token_user, token_password, token_realm_name):
    """ロール作成
    Args:
        realm_name (str): realm name
        realm_role_name (str): realm role name
        token_user (str): token 取得用 user name
        token_password (str): token 取得用 user password
        token_realm_name (str): token 取得用 realm name
    Returns:
        Response: HTTP Respose
    """
    
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_role_create: role_name:{}'.format(realm_role_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        data_para = {
            "name": realm_role_name,
        }

        globals.logger.debug("realm_role post送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        globals.logger.debug(data_para)

        request_response = requests.post("{}/auth/admin/realms/{}/roles".format(api_url, realm_name), headers=header_para, data=json.dumps(data_para))
        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 201:
            raise Exception("realm_create error status:{}, response:{}".format(request_response.status_code, request_response.text))

        globals.logger.debug("realm_role create Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_realm_role_get(realm_name, role_name, token_user, token_password, token_realm):
    """ロール情報取得
    Args:
        realm_name (str): realm name
        role_name (str): role name
        token_user (str): token user name
        token_password (str): token user password
        token_realm (str): token realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_role_get: role_name:{}'.format(role_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm)),
        }
        data_para = {
            "search": role_name,
        }
        globals.logger.debug("role get送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        globals.logger.debug(data_para)
        request_response = requests.get("{}/auth/admin/realms/{}/roles/".format(api_url, realm_name), headers=header_para, data=data_para)
        globals.logger.debug(request_response.text)
        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 200:
            raise Exception("role_get error status:{}, response:{}".format(request_response.status_code, request_response.text))

        response_data = json.loads(request_response.text)

        for role_info in response_data:
            if role_info['name'] == role_name:
                globals.logger.debug("role get Succeed!")
                # 正常応答
                return role_info

        globals.logger.debug('role not found: {}'.format(role_name))
        return
    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_user_role_get(realm_name, user_id, client_id, token_user, token_password, token_realm):
    """ユーザロール情報取得 user role info get
    Args:
        realm_name (str): realm name
        user_id (str): user id
        client_id (str): client id
        token_user (str): token user name
        token_password (str): token user password
        token_realm (str): token realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_user_role_get: realm_name:{}, user_id:{}, client_id:{}'.format(realm_name, user_id, client_id))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm)),
        }

        globals.logger.debug("user role get送信")
        # 呼び出し先設定 call destination setting
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        request_response = requests.get("{}/auth/admin/realms/{}/users/{}/role-mappings/clients/{}/composite".format(api_url, realm_name, user_id, client_id), headers=header_para)
        globals.logger.debug(request_response.text)
        
        # 取得できない場合は、Exceptionを発行する if it cannot be obtained, an Exception will be thrown
        if request_response.status_code != 200:
            raise Exception("get user role error status:{}, response:{}".format(request_response.status_code, request_response.text))

        response_data = json.loads(request_response.text)

        return response_data
    
    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_role_uesrs_get(realm_name, client_id, role_name, token_user, token_password, token_realm):
    """ロール毎のユーザ情報リスト取得 get user info list for each role
    Args:
        realm_name (str): realm name
        client_id (str): client id
        role_name (str): role name
        token_user (str): token user name
        token_password (str): token user password
        token_realm (str): token realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_role_uesrs_get: realm_name:{}, client_id:{}, role_name:{}'.format(realm_name, client_id, role_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm)),
        }

        globals.logger.debug("role users get送信")
        # 呼び出し先設定 call destination setting
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        request_response = requests.get("{}/auth/admin/realms/{}/clients/{}/roles/{}/users".format(api_url, realm_name, client_id, role_name), headers=header_para)
        globals.logger.debug(request_response.text)
        
        # 取得できない場合は、Exceptionを発行する if it cannot be obtained, an Exception will be thrown
        if request_response.status_code != 200:
            raise Exception("get role users error status:{}, response:{}".format(request_response.status_code, request_response.text))

        response_data = json.loads(request_response.text)

        return response_data
    
    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_group_create(realm_name, group_name, token_user, token_password, token_realm):
    """グループ作成
    Args:
        realm_name (str): realm name
        group_name (str): group name
        token_user (str): token user name
        token_password (str): token user password
        token_realm (str): token realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_group_create: group_name:{}'.format(group_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm)),
        }

        data_para = {
            "name": group_name,
        }

        globals.logger.debug("groups post送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        globals.logger.debug(data_para)

        request_response = requests.post("{}/auth/admin/realms/{}/groups/".format(api_url, realm_name), headers=header_para, data=json.dumps(data_para))
        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 201:
            raise Exception("group_create error status:{}, response:{}".format(request_response.status_code, request_response.text))

        globals.logger.debug("group create Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_group_children_create(realm_name, parent_group_id, group_name, token_user, token_password, token_realm):
    """子グループ作成
    Args:
        realm_name (str): realm name
        parent_group_id (str): 親 group id
        group_name (str): group name
        token_user (str): token user name
        token_password (str): token user password
        token_realm (str): token realm name
    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_group_children_create: group_name:{}, parent_group_id:{}'.format(group_name, parent_group_id))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm)),
        }
        data_para = {
            "name": group_name,
        }
        globals.logger.debug("groups children post送信")

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        globals.logger.debug(data_para)

        request_response = requests.post("{}/auth/admin/realms/{}/groups/{}/children".format(api_url, realm_name, parent_group_id), headers=header_para, data=json.dumps(data_para))
        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 201:
            raise Exception("group_children_create error status:{}, response:{}".format(request_response.status_code, request_response.text))

        globals.logger.debug("group children create Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_group_get(realm_name, group_name, token_user, token_password, token_realm):
    """グループ情報取得
    Args:
        realm_name (str): realm name
        group_name (str): group name
        token_user (str): token user name
        token_password (str): token user password
        token_realm (str): token realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_group_get: group_name:{}'.format(group_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm)),
        }
        data_para = {
            "search": group_name,
        }
        globals.logger.debug("groups get送信")

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        globals.logger.debug(data_para)

        request_response = requests.get("{}/auth/admin/realms/{}/groups".format(api_url, realm_name), headers=header_para, data=data_para)
        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 200:
            raise Exception("group_get error status:{}, response:{}".format(request_response.status_code, request_response.text))

        response_data = json.loads(request_response.text)

        # グループ名検索
        ret_group_info = sub_group_found(group_name, response_data)

        if ret_group_info is not None:
            globals.logger.debug("group get Succeed!")
        else:
            globals.logger.debug('group not found: {}'.format(group_name))

        globals.logger.debug(ret_group_info)

        return ret_group_info

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def sub_group_found(search_group_name, group_info):
    """グループ名検索

    Args:
        search_group_name (str): 検索対象グループ名
        group_info (dict): group群

    Returns:
        dict: 見つかった際はgroup群、見つからない場合はNone
    """


    try:
        ret_group_info = None

        for info in group_info:
            if info['name'] == search_group_name:
                globals.logger.debug("group found! name:{}".format(search_group_name))
                # 正常応答
                ret_group_info = info
                break
            else:
                globals.logger.debug("subGroups:{}".format(len(info["subGroups"])))
                # 見つからずサブグループがあるならサブグループで再検索
                if ret_group_info is None and len(info["subGroups"]) > 0:
                    ret_group_info = sub_group_found(search_group_name, info["subGroups"])
                    # サブグループで見つかった際はそこで終了
                    if ret_group_info is not None:
                        break

        return ret_group_info

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_group_add_role_mapping(realm_name, role_name, group_name, token_user, token_password, token_realm):
    """グループロールマッピング作成
    Args:
        realm_name (str): realm name
        group_name (str): group name
        role_name (str): role name
        token_user (str): token user name
        token_password (str): token user password
        token_realm (str): token realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_group_add_role_mapping: group_name:{}, role_name:{}'.format(group_name, role_name))
        globals.logger.debug('------------------------------------------------------')

        # group情報取得
        group_info = keycloak_group_get(realm_name, group_name, token_user, token_password, token_realm)
        globals.logger.debug(group_info)

        # role情報取得
        role_info = keycloak_realm_role_get(realm_name, role_name, token_user, token_password, token_realm)
        globals.logger.debug(role_info)

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm)),
        }

        data_para = [{
            "name": role_info['name'],
            "id": role_info['id'],
        }]

        globals.logger.debug("groups role-mappings post送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        globals.logger.debug(data_para)

        request_response = requests.post("{}/auth/admin/realms/{}/groups/{}/role-mappings/realm".format(api_url, realm_name, group_info['id']), headers=header_para, data=json.dumps(data_para))
        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 204:
            raise Exception("group role-mappings create error status:{}, response:{}".format(request_response.status_code, request_response.text))
        globals.logger.debug("group role-mappings add Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_default_group_setting(realm_name, default_group_name, token_user, token_password, token_realm):
    """デフォルトグループ設定
    Args:
        realm_name (str): realm name
        default_group_name (str): default_group_name
        token_user (str): token user name
        token_password (str): token user password
        token_realm (str): token realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_default_group_setting: default_group_name:{}'.format(default_group_name))
        globals.logger.debug('------------------------------------------------------')

        # group id情報取得
        group_info = keycloak_group_get(realm_name, default_group_name, token_user, token_password, token_realm)
        globals.logger.debug(group_info)

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm)),
        }

        globals.logger.debug("default groups put送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        request_response = requests.put("{}/auth/admin/realms/{}/default-groups/{}".format(api_url, realm_name, group_info['id']), headers=header_para)
        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 204:
            raise Exception("default groups setting error status:{}, response:{}".format(request_response.status_code, request_response.text))
        globals.logger.debug("default groups setting Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_user_create(realm_name, user_name, user_password, groups, realm_roles, user_opt, token_user, token_password, token_realm_name):
    """ユーザ作成

    Args:
        realm_name (str): realm name
        user_name (str): user name
        user_password (str): user password
        groups (str array): group array
        realm_roles (str array): realm_roles array
        user_opt (dict): user parameter option
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name

    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_user_create: realm_name:{}, user_name:{}'.format(realm_name, user_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        credentials = {
            "type": "password",
            "value": "{}".format(user_password),
        }

        data_para = {
            "username": user_name,
            "groups": groups,
            "realmRoles": realm_roles,
            "credentials": [ credentials ],
        }

        # その他のオプション値はすべてそのまま受け渡す
        if user_opt is not None:
            for key in user_opt.keys():
                data_para[key] = user_opt[key]

        globals.logger.debug("user post送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        globals.logger.debug(data_para)

        request_response = requests.post("{}/auth/admin/realms/{}/users".format(api_url, realm_name), headers=header_para, data=json.dumps(data_para))

        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 201:
            raise Exception("user_create error status:{}, response:{}".format(request_response.status_code, request_response.text))

        globals.logger.debug("user create Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_admin_user_role_mapping_create(realm_name, role_name, user_name, token_user, token_password, token_realm_name):
    """管理者ユーザ ロールマッピング作成

    Args:
        realm_name (str): realm name
        role_name (str): role name
        user_name (str): user name
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name

    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_admin_user_role_mapping_create: realm_name:{}, role_name:{}, user_name:{}'.format(realm_name, role_name, user_name))
        globals.logger.debug('------------------------------------------------------')

        # role情報取得
        role_info = keycloak_realm_role_get(realm_name, role_name, token_user, token_password, token_realm_name)
        globals.logger.debug(role_info)

        # user情報取得
        user_info = keycloak_user_get(realm_name, user_name, token_user, token_password, token_realm_name)
        globals.logger.debug(user_info)

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        data_para = [{
            "id": role_info["id"],
            "name": role_info["name"]
            # "description": role_info["description"],
            # "composite": role_info["composite"],
            # "clientRole": role_info["clientRole"],
            # "containerId": role_info["containerId"]
        }]

        globals.logger.debug("admin user role mapping post送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        globals.logger.debug(data_para)

        globals.logger.debug("user_id:{}".format(user_info["id"]))
        request_response = requests.post("{}/auth/admin/realms/{}/users/{}/role-mappings/realm".format(api_url, realm_name, user_info["id"]), headers=header_para, data=json.dumps(data_para))
        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 204:
            raise Exception("admin_user_role_mapping_create error status:{}, response:{}".format(request_response.status_code, request_response.text))

        globals.logger.debug("admin user role mapping create Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_user_client_role_mapping_create(realm_name, user_id, client_id, client_roles, token):
    """ユーザークライアントロールマッピング作成 user client role-mapping create

    Args:
        realm_name (str): realm name
        user_id (str): user id
        client_id (str): client id
        client_roles (array): client roles array
        toekn (str): token

    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL {}: user_id[{}] client_id[{}] client_roles[{}]'.format(inspect.currentframe().f_code.co_name, user_id, client_id, client_roles))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(token),
        }

        data_para = client_roles

        globals.logger.debug("user client role-mapping post 送信")
        # 呼び出し先設定 requests setting
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        request_response = requests.post("{}/auth/admin/realms/{}/users/{}/role-mappings/clients/{}".format(api_url, realm_name, user_id, client_id), headers=header_para, data=json.dumps(data_para))

        globals.logger.debug(request_response.text)

        # 正常終了以外はエラー not normal end to error
        if request_response.status_code != 204:
            raise Exception("{} error status:{}, response:{}".format(inspect.currentframe().f_code.co_name, request_response.status_code, request_response.text))

        globals.logger.debug("user client role-mapping create Succeed!")

        # 正常応答 normal return
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def client_create(realm_name, namespace, redirect_protocol, redirect_host, redirect_port, token_user, token_password, token_realm_name):
    """Client生成

    Args:
        realm_name (str): realm name
        namespace (str): ツールのnamespace
        redirect_protocol (str): ツールのprotocol
        redirect_host (str): ツールのhost
        redirect_port (str): ツールのport
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name

    Returns:
        str: secret id
    """
    try:

        # client作成&client mapper作成
        try:
            client_opt = {
                "protocol": "openid-connect",
                "publicClient": False,
                "redirectUris": [
                    "{}://{}:{}/oidc-redirect/".format(redirect_protocol, redirect_host, redirect_port),
                    "{}://{}:{}/".format(redirect_protocol, redirect_host, redirect_port)
                ],
                "baseUrl": "{}://{}:{}/".format(redirect_protocol, redirect_host, redirect_port),
                "webOrigins": [],
            }
            keycloak_client_create(realm_name, namespace, client_opt, token_user, token_password, token_realm_name)

            mapping_config = {
                "id.token.claim": True,
                "access.token.claim": True,
                "claim.name": "epoch-role",
                "multivalued": True,
                "userinfo.token.claim": True,
            }
            keycloak_client_mapping_create(realm_name, namespace, "epoch-system-map-role", client_opt["protocol"], mapping_config, token_user, token_password, token_realm_name)

        except Exception as e:
            globals.logger.debug(e.args)

        # client secret取得
        try:
            # client secret取得
            secret_id = keycloak_client_secret_get(realm_name, namespace, token_user, token_password, token_realm_name)
        except Exception as e:
            globals.logger.debug(e.args)
            raise

        return secret_id

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_client_create(realm_name, client_name, client_opt, token_user, token_password, token_realm_name):
    """client作成
    Args:
        realm_name (str): realm name
        client_name (str): client name
        client_opt (dict): client parameter option
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_client_create: client_name:{}'.format(client_name))
        globals.logger.debug('------------------------------------------------------')

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }
        data_para = {
            "id": client_name,
        }

        # その他のオプション値はすべてそのまま受け渡す
        if client_opt is not None:
            for key in client_opt.keys():
                data_para[key] = client_opt[key]

        globals.logger.debug("client post送信")
        globals.logger.debug(data_para)

        # Client作成
        request_response = requests.post("{}/auth/admin/realms/{}/clients".format(api_url, realm_name), headers=header_para, data=json.dumps(data_para))
        globals.logger.debug(request_response)
        
        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 201:
            raise Exception("client_create error status:{}, response:{}".format(request_response.status_code, request_response.text))
        globals.logger.debug("client create Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise



def keycloak_client_role_create(realm_name, client_id, role, token):
    """クライアントロール作成 client role create

    Args:
        realm_name (str): realm name
        client_id (str): client id
        role (dic): role
        toekn (str): token

    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL {}: client_id[{}] role[{}]'.format(inspect.currentframe().f_code.co_name, client_id, role))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(token),
        }

        data_para = role

        globals.logger.debug("client role post send")
        # 呼び出し先設定 requests setting
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        request_response = requests.post("{}/auth/admin/realms/{}/clients/{}/roles".format(api_url, realm_name, client_id), headers=header_para, data=json.dumps(data_para))

        globals.logger.debug(request_response.text)

        # 正常終了以外はエラー not normal end to error
        if request_response.status_code != 201:
            raise Exception("{} error status:{}, response:{}".format(inspect.currentframe().f_code.co_name, request_response.status_code, request_response.text))

        globals.logger.debug("client role create Succeed!")

        # 正常応答 normal return
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_client_role_get(realm_name, client_id, role_name, token):
    """クライアントロール情報取得 client role create get

    Args:
        realm_name (str): realm name
        client_id (str): client id
        role_name (str): role name
        toekn (str): token

    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL {}: client_id[{}] role_name[{}]'.format(inspect.currentframe().f_code.co_name, client_id, role_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(token),
        }

        globals.logger.debug("client role get send")
        # 呼び出し先設定 requests setting
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        request_response = requests.get("{}/auth/admin/realms/{}/clients/{}/roles/{}".format(api_url, realm_name, client_id, role_name), headers=header_para)

        globals.logger.debug(request_response.text)

        # 正常終了以外はエラー not normal end to error
        if request_response.status_code != 200:
            raise Exception("{} error status:{}, response:{}".format(inspect.currentframe().f_code.co_name, request_response.status_code, request_response.text))

        globals.logger.debug("client role get Succeed!")

        # 正常応答 normal return
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_client_role_composite_create(realm_name, client_id, role_name, composite_roles, token):
    """クライアントロール集合体作成 client role composite create

    Args:
        realm_name (str): realm name
        client_id (str): client id
        role_name (str): role name
        composite_roles (dic): composite roles
        toekn (str): token

    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL {}: client_id[{}] role_name[{}] composite_roles[{}]'.format(inspect.currentframe().f_code.co_name, client_id, role_name, composite_roles))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(token),
        }

        data_para = composite_roles

        globals.logger.debug("client role composite post send")
        # 呼び出し先設定 requests setting
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        request_response = requests.post("{}/auth/admin/realms/{}/clients/{}/roles/{}/composites".format(api_url, realm_name, client_id, role_name), headers=header_para, data=json.dumps(data_para))

        globals.logger.debug(request_response.text)

        # 正常終了以外はエラー not normal end to error
        if request_response.status_code != 204:
            raise Exception("{} error status:{}, response:{}".format(inspect.currentframe().f_code.co_name, request_response.status_code, request_response.text))

        globals.logger.debug("client role composite create Succeed!")

        # 正常応答 normal return
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_client_mapping_create(realm_name, client_id, client_mapping_name, client_protocol, mapping_config, token_user, token_password, token_realm_name):
    """Client Mapping作成
    Args:
        realm_name (str): realm name
        client_id (str): client id
        client_mapping_name (str): client mapping name
        client_protocol (str): client protocol
        mapping_config (dict): mapping config
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_client_mapping_create: client_mapping_name:{}'.format(client_mapping_name))
        globals.logger.debug('------------------------------------------------------')

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }
        data_para = {
            "name": client_mapping_name,
            "protocol": client_protocol,
            "protocolMapper": "oidc-usermodel-realm-role-mapper",
            "config": {
                "id.token.claim": "true",
                "access.token.claim": "true",
                "claim.name": "epoch-role",
                "multivalued": "true",
                "userinfo.token.claim": "true"
            }
        }

        # その他のオプション値はすべてそのまま受け渡す
        if mapping_config is not None:
            for key in mapping_config.keys():
                data_para["config"][key] = mapping_config[key]

        globals.logger.debug("client mapping post送信")
        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])
        globals.logger.debug(data_para)

        # Client Mapping作成
        request_response = requests.post("{}/auth/admin/realms/{}/clients/{}/protocol-mappers/models".format(api_url, realm_name, client_id), headers=header_para, data=json.dumps(data_para))
        globals.logger.debug(request_response.text)

        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 201:
            raise Exception("client mapping create error status:{}, response:{}".format(request_response.status_code, request_response.text))

        globals.logger.debug("client mapping create Succeed!")

        # 正常応答
        return request_response.text

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_client_secret_get(realm_name, client_id, token_user, token_password, token_realm_name):
    """client sercret 取得
    Args:
        realm_name (str): realm name
        client_id (str): client id
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name
    Returns:
        str: secret id
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_client_secret_get: id_of_client:{}'.format(client_id))
        globals.logger.debug('------------------------------------------------------')

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        globals.logger.debug("client secret get")
        # Client作成
        request_response = requests.get("{}/auth/admin/realms/{}/clients/{}/client-secret".format(api_url, realm_name, client_id), headers=header_para)
        globals.logger.debug(request_response.text)
        
        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 200:
            raise Exception("client_secret_get error status:{}, response:{}".format(request_response.status_code, request_response.text))
        globals.logger.debug("client secret get Succeed!")
        
        json_ret = json.loads(request_response.text)
        # 正常応答
        return json_ret["value"]

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_client_get(realm_name, client_id, token_user, token_password, token_realm_name):
    """client情報取得
    Args:
        realm_name (str): realm name
        client_id (str): client id
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name
    Returns:
        str: secret id
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_client_get: id_of_client:{}'.format(client_id))
        globals.logger.debug('------------------------------------------------------')

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        globals.logger.debug("client get")

        # Client情報取得
        request_response = requests.get("{}/auth/admin/realms/{}/clients/{}".format(api_url, realm_name, client_id), headers=header_para)
        
        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 200:
            globals.logger.debug("client get error status:{}, response:{}".format(request_response.status_code, request_response.text))
        else:
            globals.logger.debug(request_response.text)
            globals.logger.debug("client get Succeed!")
        
        return request_response.text        

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def keycloak_user_get(realm_name, user_name, token_user, token_password, token_realm_name):
    """ユーザ情報取得
    Args:
        realm_name (str): realm name
        user_name (str): user name
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_user_get: realm_name:{}, user_name:{}'.format(realm_name, user_name))
        globals.logger.debug('------------------------------------------------------')

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        globals.logger.debug("user get")
        # ユーザ情報取得
        request_response = requests.get("{}/auth/admin/realms/{}/users?search={}".format(api_url, realm_name, user_name), headers=header_para)
        globals.logger.debug(request_response.text)
        
        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 200:
            raise Exception("user_get error status:{}, response:{}".format(request_response.status_code, request_response.text))
        globals.logger.debug("user get Succeed!")
        
        user_info = json.loads(request_response.text)
        # 正常応答
        return user_info[0]

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_user_get_by_id(realm_name, user_id, token_user, token_password, token_realm_name):
    """ユーザ情報取得(user id指定)
    Args:
        realm_name (str): realm name
        user_id (str): user id
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name
    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_user_get_by_id: realm_name:{}, user_id:{}'.format(realm_name, user_id))
        globals.logger.debug('------------------------------------------------------')

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        globals.logger.debug("user get by id")
        # ユーザ情報取得
        request_response = requests.get("{}/auth/admin/realms/{}/users/{}".format(api_url, realm_name, user_id), headers=header_para)
        # globals.logger.debug(request_response.text)
        
        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 200:
            raise Exception("user_get_by_id error status:{}, response:{}".format(request_response.status_code, request_response.text))
        globals.logger.debug("user get by id Succeed!")
        
        user_info = json.loads(request_response.text)

        # 正常応答
        return user_info

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_user_reset_password(realm_name, user_id, user_password, token_user, token_password, token_realm_name):
    """ユーザパスワード変更
    Args:
        realm_name (str): realm name
        user_id (str): user id
        user_password (str): user new password
        toekn_user (str): token 取得用 user name
        toekn_password (str): token 取得用 user password
        toekn_realm_name (str): token 取得用 realm name
    Returns:
        なし
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_user_reset_password: realm_name:{}, user_id:{}'.format(realm_name, user_id))
        globals.logger.debug('------------------------------------------------------')

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        header_para = {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(get_user_token(token_user, token_password, token_realm_name)),
        }

        data_para = {
            "type": "password",
            "value": user_password,
            "temporary": False,
        }

        globals.logger.debug("keycloak_user_reset_password")
        # ユーザパスワード更新
        request_response = requests.put("{}/auth/admin/realms/{}/users/{}/reset-password".format(api_url, realm_name, user_id), headers=header_para, data=json.dumps(data_para))
        globals.logger.debug(request_response.text)
        
        # 更新できない場合は、Exceptionを発行する
        if request_response.status_code != 204:
            raise Exception("keycloak_user_reset_password error status:{}, response:{}".format(request_response.status_code, request_response.text))
        globals.logger.debug("keycloak_user_reset_password id Succeed!")
        
        # 正常応答
        return

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def keycloak_client_user_get_token(realm_name, client_id, client_secret, user_id, user_password):
    """client user token取得

    Args:
        realm_name (str): realm name
        client_id (str): client id(client name)
        client_secret (str): client secret
        user_id (str): user id
        user_password (str): user pasword

    Raises:
        Exception: error

    Returns:
        json: token json
    """
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL keycloak_client_user_get_token: realm_name:{}, client_id:{}, user_id:{}'.format(realm_name, client_id, user_id))
        globals.logger.debug('------------------------------------------------------')

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        header_para = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data_para = [
            "client_id={}".format(client_id),
            # "client_secret={}".format(client_secret),
            "username={}".format(user_id),
            "password={}".format(user_password),
            "grant_type=password",
        ]

        # その他のオプション値はすべてそのまま受け渡す
        if client_secret is not None:
            data_para.append("client_secret={}".format(client_secret))

        globals.logger.debug("get token")
        # token情報取得
        request_response = requests.post("{}/auth/realms/{}/protocol/openid-connect/token".format(api_url, realm_name), headers=header_para, data="&".join(data_para))
        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 200:
            raise AuthErrorException("client_user_get_token error status:{}, response:{}".format(request_response.status_code, request_response.text))

        globals.logger.debug("get token Succeed!")

        json_ret = json.loads(request_response.text)

        # 正常応答
        return json_ret["access_token"]

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def get_user_token(user_name, password, realm_name):
    """user token取得
    Args:
        user_name (str): user name
        password (str): user password
        realm_name (str): realm name
    Returns:
        str: token
    """
    try:
        globals.logger.debug('+----- CALL get_user_token -----+')

        # 下位の取得ロジックを呼びだし
        return keycloak_client_user_get_token(realm_name, "admin-cli", None, user_name, password)
        # header_para = {
        #     "Content-Type": "application/x-www-form-urlencoded",
        # }

        # data_para = [
        #     "client_id=admin-cli",
        #     "username={}".format(user_name),
        #     "password={}".format(password),
        #     "grant_type=password",
        # ]

        # # 呼び出し先設定
        # api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        # request_response = requests.post("{}/auth/realms/{}/protocol/openid-connect/token".format(api_url, realm_name), headers=header_para, data="&".join(data_para))
        # # 取得できない場合は、Exceptionを発行する
        # if request_response.status_code != 200:
        #     raise Exception("get_user_token error status:{}, response:{}".format(request_response.status_code, request_response.text))

        # json_ret = json.loads(request_response.text)

        # # 正常応答
        # return json_ret["access_token"]

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise
