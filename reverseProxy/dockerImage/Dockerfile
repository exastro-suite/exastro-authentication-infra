FROM    centos:7

ARG     PROXY=""
RUN     if [ ! -z "${PROXY}" ]; then \
          sed -i -e "$ a PROXY=${PROXY}" /etc/yum.conf; \
        fi

RUN      curl -L -o /tmp/cjose-0.6.1.5-2.el7.x86_64.rpm https://github.com/zmartzone/mod_auth_openidc/releases/download/v2.4.0/cjose-0.6.1.5-2.el7.x86_64.rpm \
&&       curl -L -o /tmp/mod_auth_openidc-2.4.10-1.el7.x86_64.rpm https://github.com/zmartzone/mod_auth_openidc/releases/download/v2.4.10/mod_auth_openidc-2.4.10-1.el7.x86_64.rpm \
&&       yum install -y httpd mod_ssl \
&&       yum install -y epel-release \
&&       yum install -y redis hiredis \
&&       yum install -y /tmp/cjose-0.6.1.5-2.el7.x86_64.rpm /tmp/mod_auth_openidc-2.4.10-1.el7.x86_64.rpm

RUN     cp -p /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.org \
&&      sed -e '/^\s*ErrorLog\s/s|ErrorLog\s\+\S\+|ErrorLog "/dev/stderr"|' \
            -e '/^\s*CustomLog\s/s|CustomLog\s\+\S\+|CustomLog "/dev/stdout"|' \
            -e '/^\s*TransferLog\s/s|TransferLog\s\+\S\+|TransferLog "/dev/stdout"|' \
            /etc/httpd/conf/httpd.conf.org > /etc/httpd/conf/httpd.conf \
&&      cp -p /etc/httpd/conf.d/ssl.conf /etc/httpd/conf.d/ssl.conf.org \
&&      sed -e '/^\s*ErrorLog\s/s|ErrorLog\s\+\S\+|ErrorLog "/dev/stderr"|' \
            -e '/^\s*CustomLog\s/s|CustomLog\s\+\S\+|CustomLog "/dev/stdout"|' \
            -e '/^\s*TransferLog\s/s|TransferLog\s\+\S\+|TransferLog "/dev/stdout"|' \
            /etc/httpd/conf.d/ssl.conf.org > /etc/httpd/conf.d/ssl.conf \
&&      sed -i -e 's/^/#/' /etc/logrotate.d/httpd

WORKDIR /app

COPY    httpd-start.sh /app/
COPY    exastroSettingsBridge.conf /app/
COPY    epochGitlabProxy.conf /app/

RUN     chmod +x /app/httpd-start.sh \
&&      cp /app/exastroSettingsBridge.conf /etc/httpd/conf.d/. \
&&      cp /app/epochGitlabProxy.conf /etc/httpd/conf.d/.

CMD ["/bin/sh","/app/httpd-start.sh"]