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
import base64
import requests
import traceback

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
        print('------------------------------------------------------')
        print('CALL generate_system_conf: hostname:{}, host_port:{}, auth_port:{}'.format(hostname, host_port, auth_port))
        print('------------------------------------------------------')

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

        print("generate_system_conf Succeed!")

    except Exception as e:
        print(e.args)
        print(traceback.format_exc())
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
        globals.logger.debug('CALL apply_configmap_file: cm_name:{}, cm_namespace:{}'.format(cm_name, cm_namespace))
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

        globals.logger.debug("apply_configmap_file Succeed!")

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

def gateway_httpd_restart(namespace, deploy_name):
    """Deployment Roll Restart

    Args:
        namespace (str): namespace
        deploy_name (str): deplyment name
    """
    try:
        result = subprocess.check_output(["kubectl", "rollout", "restart", "deploy", "-n", namespace, deploy_name], stderr=subprocess.STDOUT)
        print(result.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print("ERROR: except subprocess.CalledProcessError")
        print("returncode:{}".format(e.returncode))
        print("output:\n{}\n".format(e.output.decode('utf-8')))
        raise
