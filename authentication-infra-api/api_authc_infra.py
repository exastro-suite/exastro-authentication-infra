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
import api_authc_infra_client
import api_authc_infra_user
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
            # Configuration file initialization - 設定ファイル初期化
            api_httpd_call.init_httpd_conf()

            # Create setting directory for client - クライアント用設定ディレクトリ作成
            api_httpd_call.mkdir_httpd_conf_client(client_namespace)

            with tempfile.TemporaryDirectory() as tempdir:
                temp_conf_path="{}/{}".format(tempdir, conf_file_name)

                # テンプレートファイルへ値埋め込み
                api_httpd_call.generate_system_conf(
                    template_file_path,
                    temp_conf_path,
                    client_redirect_host,
                    client_secret_id,
                    crypto_passphrase,
                    client_redirect_port,
                    auth_port,
                )

                # Move to the configuration file directory - 設定ファイルディレクトリに移動
                api_httpd_call.mv_httpd_conf_file(temp_conf_path, None)

                # httpd restart
                api_httpd_call.gateway_httpd_reload(cm_namespace, deploy_name)
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
        #  Port 割り当て
        # *-*-*-*-*-*-*-*
        template_path = os.environ["NODEPORT_TEMPLATE_PATH"] + "/nodeport-template.yaml"
        client_id = payload["client_id"]
        gw_namespace = os.environ["EXASTRO_AUTHC_NAMESPACE"]
        gw_deploy_name = os.environ["GATEWAY_HTTPD_DEPLOY_NAME"]
        client_port = api_httpd_call.create_nodeport(template_path, client_id, gw_namespace, gw_deploy_name)

        # *-*-*-*-*-*-*-*
        #  keycloak 設定
        # *-*-*-*-*-*-*-*
        client_namespace = payload["client_id"]
        client_redirect_protocol = payload["client_protocol"]
        client_redirect_host = payload["client_host"]
        token_user = os.environ["EXASTRO_KEYCLOAK_USER"]
        token_password = os.environ["EXASTRO_KEYCLOAK_PASSWORD"]
        token_realm_name = os.environ["EXASTRO_KEYCLOAK_MASTER_REALM"]

        # client作成&client mapper作成
        try:
            client_secret_id = api_keycloak_call.client_create(realm, client_namespace, client_redirect_protocol, client_redirect_host, client_port, token_user, token_password, token_realm_name)

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

                # Move to the configuration file directory - 設定ファイルディレクトリに移動
                api_httpd_call.mv_httpd_conf_file(conf_dest_path, None)

        except Exception as e:
            globals.logger.debug(e.args)

        return jsonify({"result": "200"}), 200

    except Exception as e:
        return common.serverError(e)

@app.route('/settings/<string:realm>/clients/<string:client_id>/route', methods=['POST'])
def post_client_route(realm, client_id):
    """

    Args:
        realm (str): realm
        client_id (str): client id
        route_id (str): route id

    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL post_client_route')
        globals.logger.debug('#' * 50)

        payload = request.json.copy()

        with tempfile.TemporaryDirectory() as tempdir:
            conf_dest_path="{}/{}.conf".format(tempdir, payload["route_id"])

            # Generate a configuration file - 設定ファイル生成
            api_httpd_call.generate_conf(os.path.join(os.environ["CONF_TEMPLATE_PATH"],payload["template_file"]), conf_dest_path, payload["render_params"])

            # Move to the configuration file directory - 設定ファイルディレクトリに移動
            api_httpd_call.mv_httpd_conf_file(conf_dest_path, client_id)

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

        try:
            # リバースプロキシサーバ再起動
            api_httpd_call.gateway_httpd_reload(namespace, deploy_name)
        except subprocess.CalledProcessError as e:
            globals.logger.debug("ERROR: except subprocess.CalledProcessError")
            globals.logger.debug("returncode:{}".format(e.returncode))
            globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
            raise

        return jsonify({"result": "200"}), 200

    except Exception as e:
        return common.serverError(e)

@app.route('/user/current', methods=['GET'])
def call_curret_user():
    """カレントユーザー処理呼び出し call current_user

    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL {}:from[{}]'.format(inspect.currentframe().f_code.co_name, request.method))
        globals.logger.debug('#' * 50)

        if request.method == 'GET':
            # クライアントロール設定
            return api_authc_infra_user.curret_user_get()
        else:
            # Error
            raise Exception("method not support!")

    except Exception as e:
        return common.server_error(e)


@app.route('/user/current/password', methods=['PUT'])
def call_curret_user_password():
    """カレントユーザーパスワード処理呼び出し call current_user pasword
    
    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL {}:from[{}]'.format(inspect.currentframe().f_code.co_name, request.method))
        globals.logger.debug('#' * 50)

        if request.method == 'PUT':
            # クライアントロール設定
            return api_authc_infra_user.curret_user_password_change()
        else:
            # Error
            raise Exception("method not support!")

    except Exception as e:
        return common.server_error(e)


@app.route('/user/<string:user_id>/roles/<string:client_id>', methods=['GET','POST'])
def call_user_role_setting(user_id, client_id):
    """ユーザークライアントロール設定呼び出し call user client role

    Args:
        user_id (str): user id
        client_id (str): client id

    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL {}:from[{}] user_id[{}] client_id[{}]'.format(inspect.currentframe().f_code.co_name, request.method, user_id, client_id))
        globals.logger.debug('#' * 50)

        if request.method == 'GET':
            # クライアントロール設定
            return api_authc_infra_user.user_client_role_get(user_id, client_id)
        elif request.method == 'POST':
            # クライアントロール設定
            return api_authc_infra_user.user_client_role_setting(user_id, client_id)
        else:
            # Error
            raise Exception("method not support!")

    except Exception as e:
        return common.server_error(e)


@app.route('/client/<string:client_id>', methods=['GET'])
def call_client_port(client_id):
    """client port情報呼び出し call client port

    Args:
        client_id (str): client id

    Returns:
        Response: HTTP Respose
    """

    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL {}:from[{}] client_id[{}]'.format(inspect.currentframe().f_code.co_name, request.method, client_id))
        globals.logger.debug('#' * 50)

        if request.method == 'GET':
            # クライアントポート取得 get client port
            return api_authc_infra_client.get_client_port(client_id)
        else:
            # Error
            raise Exception("method not support!")

    except Exception as e:
        return common.server_error(e)


@app.route('/client/<string:client_id>/role', methods=['POST'])
def call_client_role(client_id):
    """クライアントロール設定呼び出し call client role

    Args:
        client_id (str): client id

    Returns:
        Response: HTTP Respose
    """
    try:
        globals.logger.debug('#' * 50)
        globals.logger.debug('CALL {}:from[{}] client_id[{}]'.format(inspect.currentframe().f_code.co_name, request.method, client_id))
        globals.logger.debug('#' * 50)

        if request.method == 'POST':
            # クライアントロール設定
            return api_authc_infra_client.client_role_setting()
        else:
            # Error
            raise Exception("method not support!")

    except Exception as e:
        return common.server_error(e)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('API_AUTHC_INFRA_PORT', '8000')), threaded=True)
