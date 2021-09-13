FROM    centos:7

ARG     PROXY=""
RUN     if [ ! -z "${PROXY}" ]; then \
          sed -i -e "$ a PROXY=${PROXY}" /etc/yum.conf; \
        fi

RUN     yum install -y httpd \
&&      yum install -y mod_auth_openidc \
&&      yum install -y mod_ssl

WORKDIR /app

COPY    httpd-start.sh /app/
COPY    exastroSettingsBridge.conf /app/

RUN     chmod +x /app/httpd-start.sh \
&&      cp /app/exastroSettingsBridge.conf /etc/httpd/conf.d/.

CMD ["/bin/sh","/app/httpd-start.sh"]