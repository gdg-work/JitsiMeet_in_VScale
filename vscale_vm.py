#!/usr/bin/env python
"""
Creates an Ubuntu host and prints its IP address
"""

import logging
import json
import requests
import argparse
import sys
import re
import time
from collections import namedtuple
from os import environ

VSCALE_API_URL="https://api.vscale.io/v1"
SSH_KEY_FILE="/home/dgolub/.ssh/VScale.io/vscale.key"
DEFAULT_HOSTNAME='jitsi-efDaiHeer'

def o_get_logger(o_cfg) -> logging.Logger:
    "Configures the logger"
    o_log = logging.getLogger('db_sessions')
    o_log.setLevel(logging.INFO)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    o_log.addHandler(console)
    return o_log

def o_parse_cli():
    aparser = argparse.ArgumentParser()
    aparser.add_argument('-v', '--verbose', nargs='+',
    	help = 'Verbosity level (0-4), default is 0')
    aparser.add_argument('action', default='info', choices=['create', 'list', 'info', 'delete'])
    aparser.add_argument('-n', '--hostname', required=False,
    	default=DEFAULT_HOSTNAME, help='Host name to manage')
    aparser.add_argument('-t', '--tokenfile', required=False,
        default='token.asc',
    	help = 'File with authorization toren (must be readable)'
    )

    # parse args from CLI and environment variable
    l_from_env = environ.get('VSCALE_OPTIONS','').split()
    l_all_opts = l_from_env + sys.argv[1:]
    return aparser.parse_args(l_all_opts)


def s_read_token(o_cfg: "configuration namespace", logger: "logger instance") -> str:
    "reads a token from file, returns it as a string or '' if an error occurs"
    VALID_TOKEN_RE=re.compile(r'[0-9a-f]{64}', re.IGNORECASE)
    s_token = ''
    try:
        with open(o_cfg.tokenfile, 'r') as token_fio:
            s_token = token_fio.read().strip()
            logger.debug(f'Token from file: {s_token}')
    except OSError:
        logger.error('Cannot read a token from file provided')
        return ''
    if not VALID_TOKEN_RE.match(s_token):
        logger.critical('Invalid token file contents')
        return ''
    return s_token


def requests_factory(api_base: str,s_token: str, o_log: logging.Logger) -> tuple:
    """Creates requests functions with partially filled parameters.
    Parameters: 0) API base URL, 1) security token, 2) logger object
    Returns: a dict of functions ('get', 'post', 'put', 'delete')
    """
    headers = {'Content-Type':'application/json', 'X-Token': s_token}
    timeout = 60

    def _make_url(path):
        return '/'.join([api_base.rstrip('/'), path.lstrip('/')])

    def _check_response(response) -> bool:
        """checks API response, makes error/debug output, returns true
        if response is OK, False otherwise"""
        b_result = True
        if response.status_code // 100 != 2:
            b_result = False
        else:
            try:
                __ =  response.json()
            except ValueError:
                o_log.error('API doesnt return valid JSON data')
                b_result = False
        if not b_result:
            if response.headers and 'vscale-error-message' in response.headers:
                o_log.error('Error from VScale.io: {}'.format(response.headers['vscale-error-message']))
        return b_result

    def _request_wrapper(fun, *args, **kwargs):
        "Wraps 'requests' call, checks if there was an exception"
        try:
            res = fun(*args, **kwargs)
        except  requests.RequestException as e:
            o_log.error("Cannot process API call, requests error")
            raise RuntimeError(e)
        if not _check_response(res):
            o_log.error(f'Bad response from request, code {res.status_code}')
            o_log.debug(res.text)
            raise RuntimeError()
        return res

    def getter(path, params):
        response = _request_wrapper(requests.get,
            url = _make_url(path),
            headers = headers,
            timeout = timeout,
            data = json.dumps(params),
        )
        return(response.json())

    def poster(path, params):
        o_log.debug('Poster parameters: {}'.format(str(params)))
        response = _request_wrapper(requests.post,
            url = _make_url(path),
            headers = headers,
            timeout = timeout,
            json = params
        )
        return(response.json())

    def deleter(path, params):
        o_log.debug('Deleter parameters: {}'.format(str(params)))
        response = _request_wrapper(requests.delete,
            url = _make_url(path),
            headers = headers,
            timeout = timeout,
            json = params
        )
        return(response.json())

    # return from a main function
    return (getter, poster, deleter)

# class definition
Scalet = namedtuple('Scalet', 'id name ip state fqdn')

def _fill_scalet_struct(js: "Dictionary from JavaScript") -> Scalet:
    """Creates a host description from VScale-provided JSON.
    Parameters:
    1) JSON host description like:
        {'ctid': 1673289, 'name': 'mf-gate-01', 'status': 'deleted',
        'location': 'msk0', 'rplan': 'medium', 'keys': [], 'tags': [],
        'public_address': {}, 'private_address': {},
        'made_from': 'ubuntu_20.04_64_001_master',
        'hostname': 'mf-gate-01', 'created': '2020-05-21 10:40:45',
        'active': False, 'locked': True,
        'deleted': '2020-05-21 10:51:32', 'block_reason': None,
        'block_reason_custom': None, 'date_block': None}
    Returns: Scalet structure with minimal host information
    """
    needed_fields = {'ctid', 'name', 'public_address', 'state', 'hostname'}
    return Scalet(
        id    = js['ctid'],
        name  = js['name'],
        ip    = js['public_address'].get('address', ''),
        state = js['status'],
        fqdn  = js['hostname'],
    )

def l_list_hosts(getter) -> list:
    "Returns list of hosts: list of Scalet tuples"
    r = getter('/scalets', params={})
    if r:
        return [ _fill_scalet_struct(h) for h in r ]

def get_key_id(getter) -> int:
    "returns my SSH public key ID"
    r = getter('/sshkeys', params={})
    if r:
    	return r[0]['id']
    # else returns None

def i_create_host(poster, keyid, o_log, sc_name) -> int:
    """Creates a host, returns host ID
    XXX params?"""
    API_PATH = '/scalets'
    params = {
        'name'     : sc_name,
        'do_start' : True,
        'location' : 'msk0',
        'make_from': 'ubuntu_20.04_64_001_master',
        'rplan'    : 'meduim',
        'keys'     : [ keyid ]
    }
    r = poster(API_PATH, params)
    o_log.debug(str(r))
    return (r['ctid'])

def get_host_info_byid(getter, id, logger) -> Scalet:
    "returns a host information by given ID"
    API_PATH = '/scalets' + '/' + str(id)
    js = getter(API_PATH, params={})
    if not js:
        return None
    logger.debug('JSON from vscale: {}'.format(str(js)))
    return _fill_scalet_struct(js)

def find_hosts(getter, logger, ctid=0, name='', ip='') -> Scalet:
    """Поиск  хостов по одному из признаков: имени, IP, идентификатору"""

    def _b_match_host(sc, id, name, ip):
        return (sc.id == id or
            sc.name.lower() == name.lower() or
            sc.ip == ip )

    all_hosts = l_list_hosts(getter)
    if not all_hosts:   # empty list?
        return []
    return [h for h in all_hosts if _b_match_host(h, id, name, ip)]

def wait_host_boot(getter, logger, id, attempts=10, interval=10):
    """Waits until state of the host will be 'active'"""
    while attempts > 0:
        attempts -= 1
        hi = get_host_info_byid(getter, id, logger)
        if hi.state == 'started':
            logger.info(f'VM id: {id}, active')
            break
        elif hi.state == 'queued' :
            logger.debug(f"ID: {id}, state: {hi.state}, waiting...")
            time.sleep(interval)
        elif hi.state in {'stopped', 'deleted'}:
            logger.debug(f"Scalet ID {hi.id} is stopped or deleted, cannot start")
            break
        else:
            logger.info(f'Incorrect scalet ID {hi.id} state: {hi.state}')
            break
    else:
        logger.info("Timeout waiting for VM activation")
    return

def rm_host_byid(remover, id, logger):
    "removes a host by IP"
    API_PATH = '/scalets' + '/' + str(id)
    js = remover(API_PATH, params={})
    return js

def make_hosts_file(o_cfg):
    """Creates Ansible hosts file"""
    GROUP_NAME='mfgate'
    TEMPLATE="\n".join(["# Automatically generated file",
        '[{0}]', '{1}', ''])
    hf = TEMPLATE.format(GROUP_NAME, o_cfg.hostname)
    with open("Ansible/hosts", "w") as f_out:
        f_out.write(hf)

def make_ssh_config(o_host):
    CFG_TEMPLATE="""
    host = {0}
        HostName = {1}
        Port = 22
        User = root
        IdentityFile = {2}
        StrictHostKeyChecking = no
        UserKnownHostsFile = /dev/null
    """
    ssh_config_file_name = 'Ansible/ssh_config.cfg'
    with open(ssh_config_file_name, "w") as f_out:
        f_out.write(CFG_TEMPLATE.format(
          o_host.name, o_host.ip, SSH_KEY_FILE,
        ))
    return

def make_docker_env_file(ip):
    """Crestes a source file for Shell with environment variable and key inclusion"""
    CFG_TEMPLATE="""
    echo "# You need to source this file by . (dot) operator or by 'source' command"
    ssh-add -t 1h {0}
    export DOCKER_HOST='ssh://dgolub@{1}'
    """
    source_file_name="Docker/docker.env"
    with open(source_file_name, 'w') as f_out:
        f_out.write(CFG_TEMPLATE.format(
            SSH_KEY_FILE, ip
        ))
    return

def main_task(o_cfg):
    """
    Main function of the program
    """
    (getter, poster, remover) = requests_factory(VSCALE_API_URL, o_cfg.auth_token, o_cfg.logger)

    def _to_str(s: "Scalet, host information"):
        return(f'ID: {s.id}, name: {s.name}, IP: {s.ip}')

    def _list_scalets(o_cfg) -> list:
        """Запрос списка виртуалок, возвращает имена скалетов (VM) как список строк"""
        o_cfg.logger.debug('Scalets list requested')
        l_hosts = []
        hosts_list = l_list_hosts(getter)
        if hosts_list:
            l_hosts = [h.name for h in hosts_list]
            print("\n".join(l_hosts))
        return l_hosts

    def _get_info(o_cfg):
        gw_hosts = find_hosts(getter, o_cfg.logger, name=o_cfg.hostname)
        print("\n".join([_to_str(h) for h in gw_hosts]))
        return

    def _del_by_name(o_cfg):
        gw_hosts = find_hosts(getter, o_cfg.logger, name=o_cfg.hostname)
        for h in gw_hosts:
            rm_host_byid(remover, h.id, o_cfg.logger)
        return

    def _create_scalet(o_cfg):
        """Creates a scalet, i.e. a virtual machine in VScale.io cloud"""
        host_num = i_create_host(poster, o_cfg.ssh_key_id, o_cfg.logger, o_cfg.hostname)
        o_cfg.logger.debug(f"Hello, I just created a host number {host_num}!")
        wait_host_boot(getter, o_cfg.logger, host_num)
        o_cfg.logger.debug(f"Host {host_num} is activated!")
        _make_ansible_config(o_cfg)
        o_host = get_host_info_byid(getter,host_num,o_cfg.logger)
        _make_docker_config(o_host.ip)
        return

    def _make_ansible_config(o_cfg):
        make_hosts_file(o_cfg)
        gw_hosts = find_hosts(getter, o_cfg.logger, name=o_cfg.hostname)
        if gw_hosts:
            make_ssh_config(gw_hosts[0])
        return

    def _make_docker_config(o_cfg):
        make_docker_env_file(o_cfg)
        return

    hostname=o_cfg.hostname
    act2fun = {'create': _create_scalet, 'list': _list_scalets, 'info': _get_info, 'delete': _del_by_name}
    act2fun[o_cfg.action](o_cfg)
    return


if __name__ == "__main__":
    o_cfg = o_parse_cli()
    o_cfg.logger = o_get_logger(o_cfg)
    o_cfg.auth_token = s_read_token(o_cfg, o_cfg.logger)
    o_cfg.logger.debug(o_cfg)
    (getter, poster, remover) = requests_factory(VSCALE_API_URL, o_cfg.auth_token, o_cfg.logger)
    o_cfg.ssh_key_id = get_key_id(getter)
    o_cfg.logger.debug(f"Received SSH key id: {o_cfg.ssh_key_id}")

    main_task(o_cfg)
