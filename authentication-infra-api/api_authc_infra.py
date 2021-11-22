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

@app.route('/alive', methods=["GET"])
def alive():
    """死活監視

    Returns:
        Response: HTTP Respose
    """
    return jsonify({"result": "200", "time": str(datetime.now(globals.TZ))}), 200

@app.route('/settings', methods=['POST'])
def post_settings():
    """初期設定

    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL post_settings')
        globals.logger.debug('#' * 50)

        # パラメータ情報(JSON形式)
        payload = request.json.copy()

        # *-*-*-*-*-*-*-*
        #  keycloak 設定
        # *-*-*-*-*-*-*-*
        realm_name = payload["realm_name"]
        realm_opt = payload["realm_option"]
        realm_roles = payload["realm_roles"]
        groups = payload["groups"]
        group_mappings = payload["group_mappings"]
        default_group_name = payload["default_group_name"]
        users = payload["users"]
        admin_users = payload["admin_users"]

        client_namespace = payload["client_id"]
        client_redirect_protocol = payload["client_protocol"]
        client_redirect_host = payload["client_host"]
        client_redirect_port = payload["client_port"]

        token_user = os.environ["EXASTRO_KEYCLOAK_USER"]
        token_password = os.environ["EXASTRO_KEYCLOAK_PASSWORD"]
        token_realm_name = os.environ["EXASTRO_KEYCLOAK_MASTER_REALM"]

        # *-*-*-*-*-*-*-*
        #  httpd 設定
        # *-*-*-*-*-*-*-*
        template_file_path = os.environ["CONF_TEMPLATE_PATH"] + "/" + payload["conf_template"]
        conf_file_name = payload["client_id"] + ".conf"
        crypto_passphrase = os.environ["GATEWAY_CRYPTO_PASSPHRASE"]
        auth_protocol = os.environ["EXASTRO_KEYCLOAK_PROTOCOL"]
        auth_host = os.environ["EXASTRO_KEYCLOAK_HOST"]
        auth_port = os.environ["EXASTRO_KEYCLOAK_PORT"]

        cm_name = os.environ["GATEWAY_HTTPD_CONF_CM_NAME"]
        cm_namespace = os.environ["EXASTRO_AUTHC_NAMESPACE"]
        deploy_name = os.environ["GATEWAY_HTTPD_DEPLOY_NAME"]

        # realm作成
        try:
            api_keycloak_call.keycloak_realm_create(realm_name, realm_opt, token_user, token_password, token_realm_name)

        except Exception as e:
            globals.logger.debug(e.args)

        # role作成(配列数分処理)
        for role in realm_roles:
            try:
                api_keycloak_call.keycloak_realm_role_create(realm_name, role, token_user, token_password, token_realm_name)
            except Exception as e:
                globals.logger.debug(e.args)

        # group作成(指定グループ数分処理)
        for group in groups:
            # 親グループがない場合は、TOPグループとして生成
            if len(group["parent_group"]) == 0:
                try:
                    api_keycloak_call.keycloak_group_create(realm_name, group["group_name"], token_user, token_password, token_realm_name)
                except Exception as e:
                    globals.logger.debug(e.args)
            else:
                # child group作成
                try:
                    # 作成したgroup id取得
                    parent_group = api_keycloak_call.keycloak_group_get(realm_name, group["parent_group"], token_user, token_password, token_realm_name)
                    # child group作成
                    api_keycloak_call.keycloak_group_children_create(realm_name, parent_group["id"], group["group_name"], token_user, token_password, token_realm_name)
                except Exception as e:
                    globals.logger.debug(e.args)

        # group mapping作成(指定グループマッピング数分処理)
        for mappings in group_mappings:
            try:
                api_keycloak_call.keycloak_group_add_role_mapping(realm_name, mappings["role_name"], mappings["group_name"], token_user, token_password, token_realm_name)
            except Exception as e:
                globals.logger.debug(e.args)

        # default group設定
        try:
            api_keycloak_call.keycloak_default_group_setting(realm_name, default_group_name, token_user, token_password, token_realm_name)
        except Exception as e:
            globals.logger.debug(e.args)

        # user作成(指定ユーザー数分処理)
        for user in users:
            try:
                api_keycloak_call.keycloak_user_create(realm_name, user["user_name"], user["user_password"], user["user_groups"], user["user_realm_roles"], user["user_option"], token_user, token_password, token_realm_name)
            except Exception as e:
                globals.logger.debug(e.args)

        # admin user作成(指定ユーザー数分処理)
        for admin_user in admin_users:
            try:
                api_keycloak_call.keycloak_user_create("master", admin_user["user_name"], admin_user["user_password"], admin_user["user_groups"], admin_user["user_realm_roles"], admin_user["user_option"], token_user, token_password, token_realm_name)
                # admin user role mapping作成
                api_keycloak_call.keycloak_admin_user_role_mapping_create("master", "admin", admin_user["user_name"], token_user, token_password, token_realm_name)
            except Exception as e:
                globals.logger.debug(e.args)

        # client作成&client mapper作成
        try:
            client_secret_id = api_keycloak_call.client_create(realm_name, client_namespace, client_redirect_protocol, client_redirect_host, client_redirect_port, token_user, token_password, token_realm_name)

        except Exception as e:
            globals.logger.debug(e.args)
            globals.logger.debug(traceback.format_exc())

        # httpd 設定
        try:
            with tempfile.TemporaryDirectory() as tempdir:
                conf_dest_path="{}/{}".format(tempdir, conf_file_name)

                # テンプレートファイルへ値埋め込み
                api_httpd_call.generate_system_conf(
                    template_file_path,
                    conf_dest_path,
                    client_redirect_host,
                    client_secret_id,
                    crypto_passphrase,
                    client_redirect_port,
                    auth_port,
                )

                # テンプレートファイルの適用処理
                api_httpd_call.apply_configmap_file(cm_name, cm_namespace, conf_dest_path)

                # httpd restart
                api_httpd_call.gateway_httpd_reload(cm_namespace, deploy_name, conf_file_name)
        except Exception as e:
            globals.logger.debug(e.args)

        return jsonify({"result": "200"}), 200

    except Exception as e:
        return common.serverError(e)

@app.route('/settings/<string:realm>/clients', methods=['POST'])
def post_client(realm):
    """client生成用呼び出し

    Args:
        realm (string): realm名

    Returns:
        Response: HTTP Respose
    """
    globals.logger.debug('CALL post_client:{}'.format(realm))

    try:
        # パラメータ情報(JSON形式)
        payload = request.json.copy()

        # *-*-*-*-*-*-*-*
        #  keycloak 設定
        # *-*-*-*-*-*-*-*
        client_namespace = payload["client_id"]
        client_redirect_protocol = payload["client_protocol"]
        client_redirect_host = payload["client_host"]
        client_redirect_port = payload["client_port"]
        token_user = os.environ["EXASTRO_KEYCLOAK_USER"]
        token_password = os.environ["EXASTRO_KEYCLOAK_PASSWORD"]
        token_realm_name = os.environ["EXASTRO_KEYCLOAK_MASTER_REALM"]

        # client作成&client mapper作成
        try:
            client_secret_id = api_keycloak_call.client_create(realm, client_namespace, client_redirect_protocol, client_redirect_host, client_redirect_port, token_user, token_password, token_realm_name)

        except Exception as e:
            globals.logger.debug(e.args)
            globals.logger.debug(traceback.format_exc())

        # *-*-*-*-*-*-*-*
        #  httpd 設定
        # *-*-*-*-*-*-*-*
        template_file_path = os.environ["CONF_TEMPLATE_PATH"] + "/" + payload["conf_template"]
        conf_file_name = payload["client_id"] + ".conf"
        crypto_passphrase = os.environ["GATEWAY_CRYPTO_PASSPHRASE"]
        auth_host = os.environ["EXASTRO_KEYCLOAK_HOST"]
        auth_protocol = os.environ["EXASTRO_KEYCLOAK_PROTOCOL"]
        auth_port = os.environ["EXASTRO_KEYCLOAK_PORT"]
        client_host = payload["client_host"]
        client_protocol = payload["client_protocol"]
        client_port = payload["client_port"]
        client_id = payload["client_id"]
        client_secret = client_secret_id
        backend_url = payload["backend_url"]

        cm_name = os.environ["GATEWAY_HTTPD_CONF_CM_NAME"]
        cm_namespace = os.environ["EXASTRO_AUTHC_NAMESPACE"]

        try:
            with tempfile.TemporaryDirectory() as tempdir:
                conf_dest_path="{}/{}".format(tempdir, conf_file_name)

                # テンプレートファイルへ値埋め込み
                api_httpd_call.generate_client_conf(
                    template_file_path,
                    conf_dest_path,
                    realm,
                    crypto_passphrase,
                    auth_host,
                    auth_protocol,
                    auth_port,
                    client_host,
                    client_protocol,
                    client_port,
                    client_id,
                    client_secret,
                    backend_url,
                )

                # テンプレートファイルの適用処理
                api_httpd_call.apply_configmap_file(cm_name, cm_namespace, conf_dest_path)

        except Exception as e:
            globals.logger.debug(e.args)

        # *-*-*-*-*-*-*-*
        #  nodePort 設定
        # *-*-*-*-*-*-*-*
        client_id = payload["client_id"]
        client_redirect_port = payload["client_port"]
        svc_template_file_path = os.environ["NODEPORT_TEMPLATE_PATH"] + "/nodeport-template.yaml"
        svc_file_name = "{}-svc.yaml".format(client_id)
        namespace = os.environ["EXASTRO_AUTHC_NAMESPACE"]
        deploy_name = os.environ["GATEWAY_HTTPD_DEPLOY_NAME"]

        try:
            with tempfile.TemporaryDirectory() as tempdir:
                svc_dest_path="{}/{}".format(tempdir, svc_file_name)

                api_httpd_call.render_svc_template(
                    svc_template_file_path,
                    svc_dest_path,
                    client_id,
                    client_redirect_port,
                    namespace,
                    deploy_name
                )

                api_httpd_call.apply_svc_file(svc_dest_path)

        except Exception as e:
            globals.logger.debug(e.args)
            globals.logger.debug(traceback.format_exc())
            raise

        return jsonify({"result": "200"}), 200

    except Exception as e:
        return common.serverError(e)


@app.route('/apply_settings', methods=['PUT'])
def apply_settings():
    """リバースプロキシ設定反映

    Returns:
        Response: HTTP Respose
    """
    globals.logger.debug('CALL apply_settings:')

    try:
        namespace = os.environ["EXASTRO_AUTHC_NAMESPACE"]
        deploy_name = os.environ["GATEWAY_HTTPD_DEPLOY_NAME"]

        # *-*-*-*-*-*-*-*
        #  httpd 設定
        # *-*-*-*-*-*-*-*
        conf_file_name = "epoch-ws-1-sonarqube.conf"

        try:
            # リバースプロキシサーバ再起動
            # result = subprocess.check_output(["kubectl", "rollout", "restart", "deploy", "-n", namespace, deploy_name], stderr=subprocess.STDOUT)
            # globals.logger.debug(result.decode('utf-8'))
            api_httpd_call.gateway_httpd_reload(namespace, deploy_name, conf_file_name)
        except subprocess.CalledProcessError as e:
            globals.logger.debug("ERROR: except subprocess.CalledProcessError")
            globals.logger.debug("returncode:{}".format(e.returncode))
            globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
            raise

        return jsonify({"result": "200"}), 200

    except Exception as e:
        return common.serverError(e)


@app.route('/user/current', methods=['GET'])
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
        realm_name = get_current_realm(request.headers)

        # user_idの取得
        user_id = get_current_user(request.headers)

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


@app.route('/user/current/password', methods=['PUT'])
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
        realm_name = get_current_realm(request.headers)

        # user_idの取得
        user_id = get_current_user(request.headers)

        # client_nameの取得
        client_name = get_current_client_name(request.headers)

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


@app.route('/client/<string:client_id>', methods=['GET'])
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
        realm_name = get_current_realm(request.headers)

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


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('API_AUTHC_INFRA_PORT', '8000')), threaded=True)
