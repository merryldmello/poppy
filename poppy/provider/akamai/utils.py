# Copyright (c) 2013 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import OpenSSL
import six
import socket
import ssl
import sys

from kazoo import client
from ndg.httpsclient.subj_alt_name import SubjectAltName
from OpenSSL import crypto
from OpenSSL import SSL
from oslo_log import log
from pyasn1.codec.der import decoder as der_decoder

LOG = log.getLogger(__name__)

# Python 3 does not have ssl.PROTOCOL_SSLv2, but has PROTOCOL_TLSv1_1,
# PROTOCOL_TLSv1_2, and for some reason Jenkins will not pil up these
# new versions
try:
    if six.PY2:
        extra_versions = [ssl.PROTOCOL_SSLv2]    # pragma: no cover
    if six.PY3:                                  # pragma: no cover
        extra_versions = [ssl.PROTOCOL_TLSv1_1,  # pragma: no cover
                          ssl.PROTOCOL_TLSv1_2]  # pragma: no cover
except AttributeError:                           # pragma: no cover
    extra_versions = []                          # pragma: no cover

ssl_versions = [
    ssl.PROTOCOL_TLSv1,
    ssl.PROTOCOL_SSLv23
]

try:
    # Warning from python documentation "SSL version 3 is insecure.
    # Its use is highly discouraged."
    # https://docs.python.org/2/library/ssl.html#ssl.PROTOCOL_SSLv3
    ssl_versions.append(ssl.PROTOCOL_SSLv3)
except AttributeError:   # pragma: no cover
    pass                 # pragma: no cover

ssl_versions.extend(extra_versions)


def get_ssl_number_of_hosts(remote_host):
    """Get number of Alternative names for a (SAN) Cert."""

    LOG.info("Checking number of hosts for {0}".format(remote_host))
    for ssl_version in ssl_versions:
        try:
            cert = ssl.get_server_certificate((remote_host, 443),
                                              ssl_version=ssl_version)
        except ssl.SSLError:
            # This exception m
            continue

        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        sans = []
        for idx in range(0, x509.get_extension_count()):
            extension = x509.get_extension(idx)
            if extension.get_short_name() == 'subjectAltName':
                sans = [san.replace('DNS:', '') for san
                        in str(extension).split(',')]
                break

        # We can actually print all the Subject Alternative Names
        # for san in sans:
        #     print(san)
        result = len(sans)
        break
    else:
        raise ValueError(
            'Get remote host certificate {0} info failed.'.format(remote_host))
    return result


def get_sans_by_host(remote_host):
    """Get Subject Alternative Names for a (SAN) Cert."""

    LOG.info("Retrieving sans for {0}".format(remote_host))
    for ssl_version in ssl_versions:
        try:
            cert = ssl.get_server_certificate(
                (remote_host, 443),
                ssl_version=ssl_version
            )
        except ssl.SSLError:
            # This exception m
            continue

        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        sans = []
        for idx in range(0, x509.get_extension_count()):
            extension = x509.get_extension(idx)
            if extension.get_short_name() == 'subjectAltName':
                sans = [
                    san.replace('DNS:', '').strip() for san in
                    str(extension).split(',')
                ]
                break

        # accumulate all sans across multiple versions
        result = sans
        break
    else:
        raise ValueError(
            'Get remote host certificate {0} info failed.'.format(remote_host))
    return result


def _build_context():
    import _ssl
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= getattr(_ssl, "OP_NO_COMPRESSION", 0)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    except AttributeError:
        context = None

    return context


def pyopenssl_callback(conn, cert, errno, depth, ok):
    if depth == 0 and (errno == 9 or errno == 10):
        return False
    return True


def _get_cert_alternate(remote_host):
    try:
        context = ssl.create_default_context()
    except AttributeError:
        context = _build_context()

    if context:
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=remote_host
        )
        conn.connect((remote_host, 443))
        cert = conn.getpeercert()
    else:
        context = SSL.Context(SSL.TLSv1_METHOD)
        context.set_options(SSL.OP_NO_SSLv2)
        context.set_options(SSL.OP_NO_SSLv3)
        context.set_verify(
            SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
            pyopenssl_callback
        )
        conn = SSL.Connection(context, socket.socket(socket.AF_INET))
        conn.connect((remote_host, 443))
        conn.set_connect_state()
        conn.set_tlsext_host_name(remote_host)
        conn.do_handshake()
        cert = conn.get_peer_certificate()

    conn.close()

    return cert


def get_subject_alternates(cert):
    general_names = SubjectAltName()
    subject_alternates = []

    for items in range(cert.get_extension_count()):
        ext = cert.get_extension(items)
        if ext.get_short_name() == 'subjectAltName':
            ext_dat = ext.get_data()
            decoded_dat = der_decoder.decode(ext_dat, asn1Spec=general_names)

            for name in decoded_dat:
                if isinstance(name, SubjectAltName):
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        subject_alternates.append(
                            str(component.getComponent())
                        )
    return subject_alternates


def get_ssl_number_of_hosts_alternate(remote_host):
    LOG.info("Checking number of hosts for {0}".format(remote_host))

    cert = _get_cert_alternate(remote_host)

    if isinstance(cert, OpenSSL.crypto.X509):
        return len(get_subject_alternates(cert))
    return len([
        san for record_type, san in cert['subjectAltName']
        if record_type == 'DNS'
    ])


def get_sans_by_host_alternate(remote_host):
    LOG.info("Retrieving sans for {0}".format(remote_host))

    cert = _get_cert_alternate(remote_host)

    if isinstance(cert, OpenSSL.crypto.X509):
        return get_subject_alternates(cert)
    return [
        san for record_type, san in cert['subjectAltName']
        if record_type == 'DNS'
    ]


def connect_to_zookeeper_storage_backend(conf):
    """Connect to a zookeeper cluster"""
    storage_backend_hosts = ','.join(['%s:%s' % (
        host, conf.storage_backend_port)
        for host in
        conf.storage_backend_host])
    zk_client = client.KazooClient(storage_backend_hosts)
    zk_client.start()
    return zk_client


def connect_to_zookeeper_queue_backend(conf):
    """Connect to a zookeeper cluster"""
    storage_backend_hosts = ','.join(['%s:%s' % (
        host, conf.queue_backend_port)
        for host in
        conf.queue_backend_host])
    zk_client = client.KazooClient(storage_backend_hosts)
    zk_client.start()
    return zk_client


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print('Usage: %s <remote_host_you_want_get_cert_on>' % sys.argv[0])
        sys.exit(0)
    print("There are %s DNS names for SAN Cert on %s" % (
        get_ssl_number_of_hosts(sys.argv[1]), sys.argv[1]))
