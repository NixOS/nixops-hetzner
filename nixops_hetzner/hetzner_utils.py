# -*- coding: utf-8 -*-

import time
import socket
import struct


def ping_tcp_port(host, port, timeout=1, ensure_timeout=False):
    """
    Return to True or False depending on being able to connect the specified host and port.
    Raises exceptions which are not related to opening a socket to the target host.
    """
    infos = socket.getaddrinfo(host, port, 0, 0, socket.IPPROTO_TCP)
    for info in infos:
        s = socket.socket(info[0], info[1])
        s.settimeout(timeout)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        try:
            s.connect(info[4])
        except socket.timeout:
            # try next address
            continue
        except EnvironmentError:
            # Reset, Refused, Aborted, No route to host
            if ensure_timeout:
                time.sleep(timeout)
            # continue with the next address
            continue
        except:
            raise
        else:
            s.shutdown(socket.SHUT_RDWR)
            return True
    return False


def wait_for_tcp_port(ip, port, timeout=-1, open=True, callback=None):
    """Wait until the specified TCP port is open or closed."""
    n = 0
    while True:
        if ping_tcp_port(ip, port, ensure_timeout=True) == open:
            return True
        if not open:
            time.sleep(1)
        n = n + 1
        if timeout != -1 and n >= timeout:
            break
        if callback:
            callback()
    raise Exception("timed out waiting for port {0} on ‘{1}’".format(port, ip))
