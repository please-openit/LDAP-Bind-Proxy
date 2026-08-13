FROM python:3.14-alpine

RUN adduser --disabled-password user -h /home/user

WORKDIR /opt/ldapoidc

ADD ldap_bind_proxy.py .
ADD requirements.txt .

RUN pip install -r requirements.txt

USER user

ENTRYPOINT [ "python", "/opt/ldapoidc/ldap_bind_proxy.py" ]
