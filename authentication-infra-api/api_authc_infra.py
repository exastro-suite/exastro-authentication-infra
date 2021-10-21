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
        users = payload["users"]

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

        # user作成(指定ユーザー数分処理)
        for user in users:
            try:
                api_keycloak_call.keycloak_user_create(realm_name, user["user_name"], user["user_password"], user["user_groups"], user["user_realm_roles"], user["user_option"], token_user, token_password, token_realm_name)
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
            client_secret_id = client_create(realm, client_namespace, client_redirect_protocol, client_redirect_host, client_redirect_port, token_user, token_password, token_realm_name)

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
                generate_client_conf(
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
                apply_configmap_file(cm_name, cm_namespace, conf_dest_path)

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

                render_svc_template(
                    svc_template_file_path,
                    svc_dest_path,
                    client_id,
                    client_redirect_port,
                    namespace,
                    deploy_name
                )

                apply_svc_file(svc_dest_path)

        except Exception as e:
            globals.logger.debug(e.args)
            globals.logger.debug(traceback.format_exc())
            raise

        return jsonify({"result": "200"}), 200

    except Exception as e:
        return common.serverError(e)


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
                "redirectUris": ["{}://{}:{}/oidc-redirect/".format(redirect_protocol, redirect_host, redirect_port)],
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

        header_para = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        data_para = [
            "client_id=admin-cli",
            "username={}".format(user_name),
            "password={}".format(password),
            "grant_type=password",
        ]

        # 呼び出し先設定
        api_url = "{}://{}:{}".format(os.environ['API_KEYCLOAK_PROTOCOL'], os.environ['API_KEYCLOAK_HOST'], os.environ['API_KEYCLOAK_PORT'])

        request_response = requests.post("{}/auth/realms/{}/protocol/openid-connect/token".format(api_url, realm_name), headers=header_para, data="&".join(data_para))
        # 取得できない場合は、Exceptionを発行する
        if request_response.status_code != 200:
            raise Exception("get_user_token error status:{}, response:{}".format(request_response.status_code, request_response.text))

        json_ret = json.loads(request_response.text)

        # 正常応答
        return json_ret["access_token"]

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def generate_client_conf(template_file_path, conf_dest_path, realm, crypto_passphrase, auth_host, auth_protocol, auth_port,
                            client_host, client_protocol, client_port, client_id, client_secret, backend_url):
    """Generate Client Apcahe conf

    Args:
        template_file_path (str): テンプレートファイルパス
        conf_dest_path (str): 設定ファイル出力先パス
        realm (str): realm name
        crypto_passphrase (str): パスフレーズ
        auth_host (str): keycloak host
        auth_protocol (str): keycloak protocol
        auth_port (str): keycloak port
        client_host (str): client host
        client_protocol (str): client protocol
        client_port (str): client port
        client_id (str): client id
        client_secret (str): client Secret
        backend_url (str): backend_url
    """
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL generate_client_conf: auth_host:{}, auth_protocol:{}, auth_port:{}, client_host:{}, client_protocol:{}, client_port:{}, client_id:{}' \
                                .format(auth_host, auth_protocol, auth_port, client_host, client_protocol, client_port, client_id))
        globals.logger.debug('------------------------------------------------------')

        # ファイル読み込み
        f = open(template_file_path, 'r', encoding='UTF-8')
        template_text = f.read()
        f.close()

        # 
        template = Template(template_text)
        conf_text = template.render(
            conf_dest_path = conf_dest_path,
            realm_name = realm,
            crypto_passphrase = crypto_passphrase,
            auth_host = auth_host,
            auth_protocol = auth_protocol,
            auth_port = auth_port,
            client_host = client_host,
            client_protocol = client_protocol,
            client_port = client_port,
            client_id = client_id,
            client_secret = client_secret,
            backend_url = backend_url
        )

        # ファイル出力
        f = open(conf_dest_path, 'w', encoding='UTF-8')
        f.write(conf_text)
        f.close()

        globals.logger.debug("generate_client_conf Succeed!")

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


def apply_configmap_file(cm_name, cm_namespace, conf_file_path):
    """configmap適用

    Args:
        cm_name (str): configmap name
        cm_namespace (str): configmap namespace
        conf_file_path (arr): configmapに含める設定ファイルのパス
    """
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL apply_configmap_files: cm_name:{}, cm_namespace:{}'.format(cm_name, cm_namespace))
        globals.logger.debug('------------------------------------------------------')

        # 登録済みのConfigMap定義を取得
        cm_yaml = subprocess.check_output(["kubectl", "get", "cm", cm_name, "-n", cm_namespace, "-o", "yaml"], stderr=subprocess.STDOUT)

        cm_yaml_dict = yaml.safe_load(cm_yaml.decode('utf-8'))

        # 不要な要素の削除
        if "annotations" in cm_yaml_dict["metadata"]:
            del cm_yaml_dict["metadata"]["annotations"]

        # 指定されたconfファイルを読み取り、そのファイル定義部分を差し替え
        fp = open(conf_file_path, "r")
        conf_text = fp.read()
        fp.close()

        cm_yaml_dict["data"][os.path.basename(conf_file_path)] = conf_text

        # 差し替え後の定義情報をyaml化
        cm_yaml_new = yaml.dump(cm_yaml_dict)

        with tempfile.TemporaryDirectory() as tempdir, open(os.path.join(tempdir, "configmap.yaml"), "w") as configmap_yaml_fp:
            configmap_yaml_path = configmap_yaml_fp.name

            # ConfigMapのyaml定義ファイルの生成
            configmap_yaml_fp.write(cm_yaml_new)
            configmap_yaml_fp.close()

            # ConfigMapのyaml定義の適用
            result = subprocess.check_output(["kubectl", "apply", "-f", configmap_yaml_path], stderr=subprocess.STDOUT)
            globals.logger.debug(result.decode('utf-8'))

        globals.logger.debug("apply_configmap_files Succeed!")

    except subprocess.CalledProcessError as e:
        globals.logger.debug("ERROR: except subprocess.CalledProcessError")
        globals.logger.debug("returncode:{}".format(e.returncode))
        globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
        raise

def render_svc_template(template_path, svc_dest_path, client_id, port, namespace, deploy_name):
    """render template

    Args:
        template_path (str): テンプレートファイルパス
        client_id (str): KEYCLOAK Client
        port (str): clientポート
    """
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL render_svc_template: client_id:{}, port:{}'.format(client_id, port))
        globals.logger.debug('------------------------------------------------------')

        # ファイル読み込み
        with open(template_path, 'r', encoding='UTF-8') as f:
            template_text = f.read()

        # 
        template = Template(template_text)
        svc_text = template.render(
            client_id=client_id,
            port=port,
            targetPort=port,
            nodePort=port,
            namespace=namespace,
            deploy_name=deploy_name
        )

        # ファイル出力
        with open(svc_dest_path, 'w', encoding='UTF-8') as f:
            f.write(svc_text)

        globals.logger.debug("render_svc_template (client_id:{}) Succeed!".format(client_id))

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise

def apply_svc_file(svc_files_path):
    """service生成

    Args:
        svc_files_path (arr): service設定ファイルパス
    """

    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL apply_svc_file: svc_files_path:{}'.format(svc_files_path))
        globals.logger.debug('------------------------------------------------------')

        # Serviceのyaml定義の適用
        result = subprocess.check_output(["kubectl", "apply", "-f", svc_files_path], stderr=subprocess.STDOUT)
        globals.logger.debug(result.decode('utf-8'))

    except subprocess.CalledProcessError as e:
        globals.logger.debug("ERROR: except subprocess.CalledProcessError")
        globals.logger.debug("returncode:{}".format(e.returncode))
        globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
        raise


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
            # result = subprocess.check_output(["kubectl", "rollout", "restart", "deploy", "-n", namespace, deploy_name], stderr=subprocess.STDOUT)
            # globals.logger.debug(result.decode('utf-8'))
            api_httpd_call.gateway_httpd_reload(namespace, deploy_name)
        except subprocess.CalledProcessError as e:
            globals.logger.debug("ERROR: except subprocess.CalledProcessError")
            globals.logger.debug("returncode:{}".format(e.returncode))
            globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
            raise

        return jsonify({"result": "200"}), 200

    except Exception as e:
        return common.serverError(e)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('API_AUTHC_INFRA_PORT', '8000')), threaded=True)
