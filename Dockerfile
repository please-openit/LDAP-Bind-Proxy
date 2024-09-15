FROM python:3.12-alpine

WORKDIR /opt/ldapoidc

ADD ldap_bind_proxy.py .
ADD requirements.txt .

RUN pip install -r requirements.txt

ENTRYPOINT [ "python", "/opt/ldapoidc/ldap_bind_proxy.py" ]