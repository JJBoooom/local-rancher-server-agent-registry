#!/usr/bin/env python

import ConfigParser
from fabric.api import *
import threading
import subprocess
import os
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - <%(levelname)s - %(message)s')
log = logging.getLogger(__name__)

def parse_conf(config_path):
    if os.path.exists(config_path):
        pass
    else:
        log.error('missing config file')
        sys.exit(1)

    conf_db = {}
    try:

        config = ConfigParser.RawConfigParser()
        config.read(config_path)

    except Exception, e: 
        log.error(e)
        sys.exit(1)


    section = 'REGISTRY'
    conf_db['registry_ip'] = clean_str(config.get(section,'ip'))
    conf_db['registry_port'] = clean_str(config.get(section,'port'))
    conf_db['registry_name'] = clean_str(config.get(section,'name'))
    conf_db['registry_store'] = clean_str(config.get(section,'store'))
    conf_db['registry_password'] = clean_str(config.get(section, 'password'))

    section = 'SERVER'
    conf_db['server_ip'] = clean_str(config.get(section,'ip'))
    conf_db['server_port'] = clean_str(config.get(section, 'port'))
    conf_db['server_password'] = clean_str(config.get(section, 'password'))

    section = 'REGISTRY_FRONTEND'
    conf_db['registry_frontend_ip'] = clean_str(config.get(section,'ip'))
    conf_db['registry_frontend_password'] = clean_str(config.get(section, 'password'))
    conf_db['registry_frontend_name'] = clean_str(config.get(section, 'name'))
    conf_db['registry_frontend_port'] = clean_str(config.get(section, 'port'))


    if not conf_db['registry_name']:  
        conf_db['registry_name'] = 'MyPrivateRegistry'
    if not conf_db['registry_port']:
        conf_db['registry_port'] = '5000'
    if not conf_db['registry_store']:
        conf_db['registry_store'] = '/var/lib/MyPrivateRegistry'
        
    if not conf_db['server_port']:
        conf_db['registry_store'] = '8080'

    if not conf_db['registry_frontend_name']:
        conf_db['registry_frontend_name'] = 'MyRegistryFrontend'

    return conf_db

def parse_agent_conf(config_path):
    if os.path.exists(config_path):
        pass
    else:
        log.error('missing config file')
        sys.exit(1)
    try:

        config = ConfigParser.RawConfigParser()
        config.read(config_path)

    except Exception, e: 
        log.error(e)

    conf_db = {}
    agents_conf = {}
    ips = {}
    pws = {}

    section = 'AGENT'
    for options in config.options(section):
        if options.startswith('ip'):
       #skip duplicate ips
       #Note: ConfigParser will auto filter duplicate option, and choose the last option's value
            #if ips.has_key(options):
            #   print 'skip duplicate option:'+options
            #    continue
            ipaddr = clean_str(config.get(section, options))
            if ipaddr:
                ips[options] = ipaddr
            else:
                log.info('skip EMPTY option:%s'%(options))
        if options.startswith('password'):
            password = clean_str(config.get(section, options))
            if password:
                pws[options] = password
    for ipkey in ips.keys():
        if agents_conf.has_key(ips[ipkey]):
            log.info('skip duplicate host:%s'%(ips[ipkey]))
            continue
        ipindex = ipkey.replace('ip', '')
        for pwkey in pws.keys():
            if ipindex == pwkey.replace('password', ''):
                agents_conf[ips[ipkey]] = pws[pwkey]
                break
    return agents_conf

class FabricSupport:
    def __init__(self, host, password):
        self.host = host
        self.port = 22
        self.password = password

    def command_run(self,command):
        if self.host == get_hostip():
            with settings(warn_only=True):
                return  local(command)
        else:
            env.host_string = "%s:%s" % (self.host, self.port)
            env.password=self.password
            with settings(warn_only=True):
                return run(command)
    def stop_container_and_rm(self):
        command = 'docker stop `docker ps -q`'
        self.command_run(command)

        command = 'docker rm -f `docker ps -a -q`'
        self.command_run(command)

    def rm_images(self):
        command = 'docker rmi -f `docker images -a -q`'
        self.command_run(command)

    

    

def get_hostip():
    try:
        hostip = subprocess.check_output(["/bin/sh", "-c", 'ip route show | grep "192.168" | grep "metric" | grep -v "default" | awk \'{print $9}\'']).strip('\n')
        log.debug("hostip:"+hostip)
        return hostip
    except Exception,e:
        log.error("Can not get host ip:"+str(e))
        sys.exit(1)

# delete the '' or "" of a string
def clean_str(var):
    del_commas = ['\'', '\"']

    if not var:
        return var
    for i in del_commas:
        if var.startswith(i) and var.endswith(i):
            return var.lstrip(i).rstrip(i)
    return var

def clean_agent(agents_conf, ip):
    fs = FabricSupport(ip, agents_conf[ip])
    fs.stop_container_and_rm()
    fs.rm_images()

def clean_other(ip, password):
    fs = FabricSupport(ip, password)
    fs.stop_container_and_rm()
    fs.rm_images()
    


def main():
    script_dir_path = os.path.abspath(os.path.dirname(sys.argv[0]))
    config_path = script_dir_path+'/conf'
    conf_db = parse_conf(config_path)
    agents_conf = parse_agent_conf(config_path)

    for i in conf_db.keys():
        print "%s:%s"%(i, conf_db[i])
    for j in agents_conf.keys():
        print '%s:%s'%(j,agents_conf[j])


    threads = []
    for ip in agents_conf.keys():
        if ip != 'rancher-server-command':
            clean_agent(agents_conf, ip)
        
    clean_other(conf_db['registry_ip'], conf_db['registry_password'])
        
    clean_other(conf_db['server_ip'], conf_db['server_password'])
        
    clean_other(conf_db['registry_frontend_ip'], conf_db['registry_frontend_password'])
        

if __name__ == '__main__':
    main()

