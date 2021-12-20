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

from typing import Awaitable
from flask import Flask, request, abort, jsonify, render_template
from datetime import datetime
import os
import json
import tempfile
import subprocess
import time
import re
import base64
import requests
import traceback
import shutil

from urllib.parse import urlparse
from requests.auth import HTTPBasicAuth
from datetime import timedelta, timezone
from jinja2 import Template

import globals
import common
import yaml

# 設定ファイル読み込み・globals初期化
app = Flask(__name__)
app.config.from_envvar('CONFIG_API_AUTHC_INFRA_PATH')
globals.init(app)

def generate_system_conf(template_path, conf_dest_path, hostname, client_secret, crypto_passphrase, host_port, auth_port):
    """Generate SYSTEM Apcahe conf

    Args:
        template_path (str): テンプレートファイルパス
        conf_dest_path (str): 設定ファイル出力先パス
        hostname (str): FQDN or IP
        client_secret (str): KEYCLOAK Client Secret
        host_port (str): system port
        auth_port (str): keycloak port
    """
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL generate_system_conf: hostname:{}, host_port:{}, auth_port:{}'.format(hostname, host_port, auth_port))
        globals.logger.debug('------------------------------------------------------')

        # ファイル読み込み
        f = open(template_path, 'r', encoding='UTF-8')
        template_text = f.read()
        f.close()

        # 
        template = Template(template_text)
        conf_text = template.render(
            epoch_port = host_port,
            crypto_passphrase = crypto_passphrase,
            server = hostname,
            auth_port = auth_port,
            epoch_system_client_secret = client_secret
        )

        # ファイル出力
        f = open(conf_dest_path, 'w', encoding='UTF-8')
        f.write(conf_text)
        f.close()

        globals.logger.debug("generate_system_conf Succeed!")

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

def generate_conf(template_file_path, conf_dest_path, render_params):
    """httpd configuration file generation - httpd設定ファイル出力

    Args:
        template_file_path (str): httpd config file template - httpd設定ファイルテンプレート
        conf_dest_path (str): httpd configuration file output destination - httpd設定ファイル出力先
        render_params (dict): Rendering parameters - レンダリングパラメータ
    """
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL generate_conf: template_file_path:{}, conf_dest_path:{}' \
                                .format(template_file_path, conf_dest_path))
        globals.logger.debug('------------------------------------------------------')

        # ファイル読み込み
        f = open(template_file_path, 'r', encoding='UTF-8')
        template_text = f.read()
        f.close()

        # 
        template = Template(template_text)
        conf_text = template.render(
            param = render_params
        )

        # ファイル出力
        f = open(conf_dest_path, 'w', encoding='UTF-8')
        f.write(conf_text)
        f.close()

    except Exception as e:
        globals.logger.debug(e.args)
        globals.logger.debug(traceback.format_exc())
        raise


# def apply_configmap_file(cm_name, cm_namespace, conf_file_path):
#     """configmap適用

#     Args:
#         cm_name (str): configmap name
#         cm_namespace (str): configmap namespace
#         conf_file_path (arr): configmapに含める設定ファイルのパス
#     """
#     try:
#         globals.logger.debug('------------------------------------------------------')
#         globals.logger.debug('CALL apply_configmap_file: cm_name:{}, cm_namespace:{}'.format(cm_name, cm_namespace))
#         globals.logger.debug('------------------------------------------------------')

#         # 登録済みのConfigMap定義を取得
#         cm_yaml = subprocess.check_output(["kubectl", "get", "cm", cm_name, "-n", cm_namespace, "-o", "yaml"], stderr=subprocess.STDOUT)

#         cm_yaml_dict = yaml.safe_load(cm_yaml.decode('utf-8'))

#         # 不要な要素の削除
#         if "annotations" in cm_yaml_dict["metadata"]:
#             del cm_yaml_dict["metadata"]["annotations"]

#         # 指定されたconfファイルを読み取り、そのファイル定義部分を差し替え
#         fp = open(conf_file_path, "r")
#         conf_text = fp.read()
#         fp.close()

#         cm_yaml_dict["data"][os.path.basename(conf_file_path)] = conf_text

#         # 差し替え後の定義情報をyaml化
#         cm_yaml_new = yaml.dump(cm_yaml_dict)

#         with tempfile.TemporaryDirectory() as tempdir, open(os.path.join(tempdir, "configmap.yaml"), "w") as configmap_yaml_fp:
#             configmap_yaml_path = configmap_yaml_fp.name

#             # ConfigMapのyaml定義ファイルの生成
#             configmap_yaml_fp.write(cm_yaml_new)
#             configmap_yaml_fp.close()

#             # ConfigMapのyaml定義の適用
#             result = subprocess.check_output(["kubectl", "apply", "-f", configmap_yaml_path], stderr=subprocess.STDOUT)
#             globals.logger.debug(result.decode('utf-8'))

#         globals.logger.debug("apply_configmap_file Succeed!")

#     except subprocess.CalledProcessError as e:
#         globals.logger.debug("ERROR: except subprocess.CalledProcessError")
#         globals.logger.debug("returncode:{}".format(e.returncode))
#         globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
#         raise

def init_httpd_conf():
    """Initialize httpd config file - httpd confファイル初期化
    """
    globals.logger.debug('------------------------------------------------------')
    globals.logger.debug('CALL init_httpd_conf')
    globals.logger.debug('------------------------------------------------------')

    globals.logger.debug('clear : {}'.format((os.environ["GATEWAY_HTTPD_CONF_PATH"] + "/*")))

    path = os.environ["GATEWAY_HTTPD_CONF_PATH"]

    for item in os.listdir(path):
        if os.path.isfile(os.path.join(path, item)):
            os.remove(os.path.join(path, item))
        else:
            shutil.rmtree(os.path.join(path, item))

def mkdir_httpd_conf_client(client_id):
    """Create directory for client settings - クライアント設定用ディレクトリ作成

    Args:
        client_id (str): client id
    """
    globals.logger.debug('------------------------------------------------------')
    globals.logger.debug('CALL mkdir_httpd_conf_client: client_id:{}'.format(client_id))
    globals.logger.debug('------------------------------------------------------')

    os.makedirs(os.path.join(os.environ["GATEWAY_HTTPD_CONF_PATH"], client_id), exist_ok=True)


def mv_httpd_conf_file(conf_file_path, client_id):
    """Place the config file in the httpd config directory - httpd設定ディレクトに設定ファイルを配置します

    Args:
        conf_file_path (str): File to move - 配置するファイル
        client_id (string): Client_id of the subdirectory for the client of the location - 配置先のclient用サブディレクトリのclient_id
    """
    globals.logger.debug('------------------------------------------------------')
    globals.logger.debug('CALL mv_httpd_conf_file: conf_file_path:{}, client_id:{}' \
                            .format(conf_file_path, client_id))
    globals.logger.debug('------------------------------------------------------')

    if client_id is None:
        dest_path = os.environ["GATEWAY_HTTPD_CONF_PATH"]
    else:
        dest_path = os.path.join(os.environ["GATEWAY_HTTPD_CONF_PATH"], client_id)

    os.makedirs(dest_path, exist_ok=True)

    shutil.move(conf_file_path, os.path.join(dest_path, os.path.basename(conf_file_path)))


def create_nodeport(template_path, client_id, gw_namespace, gw_deploy_name):
    """NodePort生成

    Args:
        template_path (str): Serviceのyamlテンプレートファイルのパス
        client_id (str): Client id
        gw_namespace (str): Gatewayのnamespace
        gw_deploy_name (str): GetewayのDeploy名

    Returns:
        int: NodePort番号
    """
    globals.logger.debug('------------------------------------------------------')
    globals.logger.debug('CALL create_nodeport: client_id:{}'.format(client_id))
    globals.logger.debug('------------------------------------------------------')

    client_port = 0

    try:
        #
        # 割り当てられたNodePortを取得（既に作成済みの場合は同じ番号を使う）
        # 
        globals.logger.debug("get service:")
        result = subprocess.check_output(["kubectl", "get", "svc", client_id, "-n", gw_namespace, "-o", "json"], stderr=subprocess.STDOUT)
        dic_result = json.loads(result.decode('utf-8'))
        client_port = dic_result["spec"]["ports"][0]["nodePort"]
        globals.logger.debug("get service client_port:{}".format(client_port))

    except subprocess.CalledProcessError as e:
        # Serviceが存在しない
        pass

    try:
        #
        # Serviceのyamlテンプレートの読み込み
        #
        with open(template_path, 'r', encoding='UTF-8') as f:
            template_text = f.read()

        template = Template(template_text)

        #
        # 仮生成(NodePortを確定させる)
        #
        with tempfile.TemporaryDirectory() as tempdir:

            # NodePortを確定するために8000番で仮生成
            svc_text = template.render(
                client_id=client_id,
                port=8000,
                targetPort=8000,
                nodePort=client_port,
                namespace=gw_namespace,
                deploy_name=gw_deploy_name
            )
            fp = open(os.path.join(tempdir, "svc.yaml"), "w")
            fp.write(svc_text)
            fp.close()

            # Serviceの適用
            globals.logger.debug("apply service (provisional):")
            result = subprocess.check_output(["kubectl", "apply", "-f", fp.name], stderr=subprocess.STDOUT)
            globals.logger.debug("\n"+result.decode('utf-8'))

        #
        # 割り当てられたNodePortを取得
        # 
        globals.logger.debug("get service:")
        result = subprocess.check_output(["kubectl", "get", "svc", client_id, "-n", gw_namespace, "-o", "json"], stderr=subprocess.STDOUT)
        dic_result = json.loads(result.decode('utf-8'))
        client_port = dic_result["spec"]["ports"][0]["nodePort"]
        globals.logger.debug("get service client_port:{}".format(client_port))

        #
        # 決定したPortでServiceを更新
        #
        with tempfile.TemporaryDirectory() as tempdir, open(os.path.join(tempdir, "svc.yaml"), "w") as fp:
            svc_text = template.render(
                client_id=client_id,
                port=8000,
                targetPort=client_port,
                nodePort=client_port,
                namespace=gw_namespace,
                deploy_name=gw_deploy_name
            )
            fp = open(os.path.join(tempdir, "svc.yaml"), "w")
            fp.write(svc_text)
            fp.close()

            # Serviceの適用
            globals.logger.debug("apply service:")
            result = subprocess.check_output(["kubectl", "apply", "-f", fp.name], stderr=subprocess.STDOUT)
            globals.logger.debug("\n"+result.decode('utf-8'))

        return client_port

    except subprocess.CalledProcessError as e:
        globals.logger.debug("ERROR: except subprocess.CalledProcessError")
        globals.logger.debug("returncode:{}".format(e.returncode))
        globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
        raise


# def apply_configmap_file(cm_name, cm_namespace, conf_file_path):
#     """configmap適用

#     Args:
#         cm_name (str): configmap name
#         cm_namespace (str): configmap namespace
#         conf_file_path (arr): configmapに含める設定ファイルのパス
#     """
#     try:
#         globals.logger.debug('------------------------------------------------------')
#         globals.logger.debug('CALL apply_configmap_files: cm_name:{}, cm_namespace:{}'.format(cm_name, cm_namespace))
#         globals.logger.debug('------------------------------------------------------')

#         # 登録済みのConfigMap定義を取得
#         cm_yaml = subprocess.check_output(["kubectl", "get", "cm", cm_name, "-n", cm_namespace, "-o", "yaml"], stderr=subprocess.STDOUT)

#         cm_yaml_dict = yaml.safe_load(cm_yaml.decode('utf-8'))

#         # 不要な要素の削除
#         if "annotations" in cm_yaml_dict["metadata"]:
#             del cm_yaml_dict["metadata"]["annotations"]

#         # 指定されたconfファイルを読み取り、そのファイル定義部分を差し替え
#         fp = open(conf_file_path, "r")
#         conf_text = fp.read()
#         fp.close()

#         cm_yaml_dict["data"][os.path.basename(conf_file_path)] = conf_text

#         # 差し替え後の定義情報をyaml化
#         cm_yaml_new = yaml.dump(cm_yaml_dict)

#         with tempfile.TemporaryDirectory() as tempdir, open(os.path.join(tempdir, "configmap.yaml"), "w") as configmap_yaml_fp:
#             configmap_yaml_path = configmap_yaml_fp.name

#             # ConfigMapのyaml定義ファイルの生成
#             configmap_yaml_fp.write(cm_yaml_new)
#             configmap_yaml_fp.close()

#             # ConfigMapのyaml定義の適用
#             result = subprocess.check_output(["kubectl", "apply", "-f", configmap_yaml_path], stderr=subprocess.STDOUT)
#             globals.logger.debug(result.decode('utf-8'))

#         globals.logger.debug("apply_configmap_files Succeed!")

#     except subprocess.CalledProcessError as e:
#         globals.logger.debug("ERROR: except subprocess.CalledProcessError")
#         globals.logger.debug("returncode:{}".format(e.returncode))
#         globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
#         raise


def gateway_httpd_reload(namespace, deploy_name):
    """gateway-httpd graceful reload

    Args:
        namespace (str): namespace
        selector_pod_name (str): selectorに渡すpod name
        conf_file_name (str): configファイル名
    """
    #gateway-httpd graceful reload
    try:
        globals.logger.debug('------------------------------------------------------')
        globals.logger.debug('CALL gateway_httpd_reload: namespace:{}, deploy_name:{}'.format(namespace, deploy_name))
        globals.logger.debug('------------------------------------------------------')

        conf_file_path = ""

        # 処理対象のgateway-httpd POD一覧を取得する
        target_pods_str = subprocess.check_output(["kubectl", "get", "pod", "-n", namespace, "-o", "json", "--selector=name=gateway-httpd"], stderr=subprocess.STDOUT)
        target_pods = json.loads(target_pods_str)

        # 処理対象のgateway-httpd PODを全て処理
        for target_pod in target_pods["items"]:
            if target_pod["status"]["phase"] == "Running":
                # 実行中(Running)のPODを処理する
                for target_pod_statuses in target_pod["status"]["containerStatuses"]:
                    if target_pod_statuses["ready"] == True:
                        # ready状態のPODを処理する

                        # timeout_cnt = 1
                        # while True:
                        #     # confファイルが生成されるまで後続の処理をしない
                        #     globals.logger.debug("[START]: httpd conf exist check :" + target_pod["metadata"]["name"])
                            
                        #     # 生成したconfファイルが存在する場合は1、存在しない場合は0を返す
                        #     file_check_result = subprocess.check_output(["kubectl", "exec", "-i", "-n", namespace, target_pod["metadata"]["name"], "--", "bash", "-c", "test -e /etc/httpd/conf.d/exastroSettings/" + conf_file_name + "&& echo 1 || echo 0"], stderr=subprocess.STDOUT)

                        #     # 存在チェックの結果に混在している、改行コードを削除
                        #     file_check_result = file_check_result.decode('utf-8').replace('\n', '')

                        #     if file_check_result == "1":
                        #         globals.logger.debug("conf file created")
                        #         break
                        #     else:
                        #         globals.logger.debug("conf file creating...")
                        #         time.sleep(5)
                        #         timeout_cnt += 1
                                
                        #         if timeout_cnt > 60:
                        #             # 5分経過したらtimeoutで失敗
                        #             globals.logger.debug("conf file create failed timeout")
                        #             raise

                        # confファイルを読み込み
                        # globals.logger.debug("[START]: httpd conf read :" + target_pod["metadata"]["name"])
                        # result = subprocess.check_output(["kubectl", "exec", "-i", "-n", namespace, target_pod["metadata"]["name"], "--", "bash", "-c", "cat /etc/httpd/conf.d/exastroSettings/*.conf"], stderr=subprocess.STDOUT)
                        # globals.logger.debug(result.decode('utf-8'))

                        # httpd -k gracefulコマンドの実行
                        globals.logger.debug("[START]: httpd graceful restart pod :" + target_pod["metadata"]["name"])
                        result = subprocess.check_output(["kubectl", "exec", "-i", "-n", namespace, target_pod["metadata"]["name"], "--", "httpd", "-k", "graceful"], stderr=subprocess.STDOUT)
                        # globals.logger.debug(result.decode('utf-8'))
                    else:
                        # ready状態じゃないPODはSKIP
                        globals.logger.debug("[SKIP]: httpd graceful restart pod :" + target_pod["metadata"]["name"])
            else:
                # 実行中じゃないPODはSKIP
                globals.logger.debug("[SKIP]: httpd graceful restart pod :" + target_pod["metadata"]["name"])
                globals.logger.debug("pod status phase :" + target_pod["status"]["phase"])

        globals.logger.debug("gateway_httpd_reload Succeed!")

    except subprocess.CalledProcessError as e:
        globals.logger.debug("ERROR: except subprocess.CalledProcessError")
        globals.logger.debug("returncode:{}".format(e.returncode))
        globals.logger.debug("output:\n{}\n".format(e.output.decode('utf-8')))
        raise
