#coding=utf-8
#!/usr/bin/env python


import subprocess
import sys
import os
import logging
import ConfigParser
import paramiko
import getpass
import re
import tempfile
import shutil
from docker import Client
from fabric.api import *

logging.basicConfig(level=logging.INFO, format='%(asctime)s - <%(levelname)s> - %(message)s')
log = logging.getLogger(__name__)

class MyException(Exception):
    pass

class Registry(object):
    
    def __init__(self, port='5000', name='MyPrivateRegistry', store='/var/lib/MyPrivateRegistry'):
        self.port = port
        self.name = name
        self.store = store
        self.ip = get_hostip() 

    #缺少端口,镜像名以及共享卷合法性认证
    def validate(self):    
        return (self.ip is not None and self.port is not None and 
            self.name is not None and
            self.store is not None)

    def display(self):
        log.debug('-----Registry conf-----')
        log.debug('ip:%s'%(self.ip))
        log.debug('port:%s'%(self.port))
        log.debug('name:%s'%(self.name))
        log.debug('store:%s'%(self.store))
        
    def check_env(self):
        with settings(warn_only=True):
            result = local('which docker', capture=True) 
        if result.failed:
            log.error('docker not intalled')
            return False
        with settings(warn_only=True): 
            result = local('docker version', capture=True)
        if result.failed and confirm('docker daemon isn\'t running, Try to start it?'):
            result = local('systemctl start docker',capture=True) 
            if result.failed:
                log.error('Can\'t start docker daemon')
                return False
        else:
            log.error('cancel to start docker daemon?')
            return False
        return True

    def load_images(self, zipped_path, images_file):
        if not zipped_path or not images_file:
            log.debug('mising arguments')
            return False
        if not os.path.exists(zipped_path) or not os.path.exists(images_file):
            log.error('missing images zipped')
            return False
        
        try:
            temp = tempfile.mkdtemp()
            log.debug('create temp dir:'+temp)
            with settings(warn_only=True): 
                result = local('cp %s %s'%(zipped_path, temp+'/'), capture=False)
            if result.failed:
                log.error('moving zipped to temp dir fail')
                return False
            
            with settings(warn_only=True):
                result = local('gunzip %s' %(temp+"/"+os.path.basename(zipped_path)))
            if result.failed:
                log.error('gunzip fail')
                return False

            onlyfiles = [os.path.join(temp,f) for f in os.listdir(temp) if os.path.isfile(os.path.join(temp, f))]
            try:
                cli = Client(base_url='unix://var/run/docker.sock', version='auto')
                for f in onlyfiles:
                    log.debug('load image:'+f)        
                    try:
                        fp = open(f, 'r')
                        try:
                            cli.load_image(fp)
                        except Exception, e:
                            log.error('load image %s fail'%(f)+stre(e))
                            return False
                        finally:
                            fp.close()
                    except Exception, e:
                        log.error('open %s fail'%(f)+str(e))
                        return False
            except Exception, e:
                log.error('connect to docker daemon fail:'+str(e))
                return False
            return True 
        except Exception, e:
            log.debug('create temp dir fail:'+str(e))
            return False
        finally:
            shutil.rmtree(temp)

    def add_registry():
        docker_conf = '/etc/sysconfig/doccker'
        if not add_insecure_registry(docker_conf, self.ip, seek.port):
            sys.exit(1)
    
    def run_registry(self):
        with settings(warn_only=True):
            result = local('docker  run -d --restart=always -p %s:%s --name %s -v %s:/var/lib/registry registry:2' %(self.ip, self.port, self.name, self.store))
        if result.failed:
            log.error('run registry fail')
            return False

        
              
class  Remote_Registry(Registry):
    def __init__(self, ip, port='5000', name='MyPrivateRegistry', store='/var/lib/MyPrivateRegistry'):
        self.port = port
        self.name = name
        self.store = store
        self.ip = ip
#        self.password = getpass.getpass('Enter a password for %s:' % (self.ip))
        
        self.password = 'Cloudsoar123'
        if not self.validate():
            log.error('Invalid argument')
            sys.exit(1)
        
        
    def validate(self):
        return self.ip != get_hostip() and self.password != None

    
    
    def check_env(self):
        env.host_string = "%s:%s"%(self.ip ,22) 
        env.password = self.password
        with quiet(), settings(warn_only=True):
            command = 'which docker'
            result = run(command, quiet=True)
            if result.failed:
                log.error('Docker command isn\'t installed')
                return False
        with settings(warn_only=True):
            command = 'docker version'
            result = run(command)
            if result.failed and confirm('docker daemon isn\'t running, Try to start it?'):
                log.info('Try to start docker daemon')
                with settings(warn_only=True):
                    command = 'systemctl start docker'
                    result = run(command)
                if result.failed:
                    log.error('start docker daemon fail')
                    return False
                else:
                    log.info('start docker daemon success')
            elif not result.failed:
                pass
            else:
                log.info('Cancel to start docker daemon')
                return False
        log.info('check enviroment:pass')
        return True
    
    def run_registry(self):
        env.host_string = "%s:%s"%(self.ip ,22) 
        env.password = self.password
        with quiet(), settings(warn_only=True):
            command = 'docker run -d --restart=always -p %s:5000 --name %s -v %s:/var/lib/registry registry:2' %(self.port, self.name, self.store)
            log.debug('command:'+command)
            result = run(command)
            if result.failed:
                log.error('run registry fail')
                return False
        return True

    def add_registry(self):
   #     add_insecure_registry(self.ip, self.port)
        env.host_string = "%s:%s"%(self.ip ,22) 
        env.password = self.password
        docker_conf = '/etc/sysconfig/docker'
        with quiet(), settings(warn_only=True):
            command = 'grep -e "^"'  
        
    
    def load_images(self, zipped_path, images_file):
        env.host_string = "%s:%s"%(self.ip ,22) 
        env.password = self.password

        if not zipped_path or not images_file:
            log.debug('mising arguments')
            sys.exit(1)
        if not os.path.exists(zipped_path) or not os.path.exists(images_file):
            log.error('missing images zipped')
            sys.exit(1)

        try:
            tempdir = ''
            with settings(warn_only=True): 
                command = 'mktemp -d /tmp/zipped.XXXXXXX'
                result = run(command)
              
                if not result.failed:
                    tempdir = result.stdout
                else:
                    log.error('%s:create tempdir fail' % (self.ip))
                    system.exit(1)

                result = put(zipped_path, tempdir)
                if result.failed:
                    log.error('%s:moving zipped to temp dir fail' % (self.ip))
                    raise MyException

                command = 'gunzip %s/%s' % (tempdir,os.path.basename(zipped_path))
                result = run(command)
                if result.failed:
                    log.error("%s:gunzip fail"%(self.ip))
                    raise MyException

                command = 'ls %s' % (tempdir)
                result = run(command)
                if result.failed:
                    log.error("%s:list file faile")%(self.ip)
                    raise MyException
                else:
                    for tfile in result.stdout.split():
                        command = 'docker load --input %s/%s'%(tempdir, tfile)
                        result = run(command)
                        if result.failed:
                            log.error('%s:load %s fail'%(self.ip, tfile))
                            raise MyException
                       
        except MyException:
            with settings(warn_only=True): 
                command = 'rm -rf %s'%(tempdir)
                result = run(command)
                sys.exit(1)
           
def add_insecure_registry(docker_conf, ip, port):
    content = '--insecure-registry %s:%s' % (ip, port)
   # docker_conf = '/etc/sysconfig/docker'
    if not os.path.exists(docker_conf):
        log.error('missing docker conf')
        sys.exit(1)

    try:
        f = open(docker_conf, 'r+')
        try:
            filedata = file.read()
            sl = list()
            for line in filedata.split('\n'):
                if re.match(r'^INSECURE_REGISTRY=', line.strip(), re.M):
                    li = line.strip().rstrip('\'')+' --insecure-registry %s:%s\''%(ip, port)
                elif re.match(r'^#INSECURE_REGISTRY=', line.strip(), re.M):
                    li = 'INSECURE_REGISTRY=\'--insecure-registry %s:%s\''%(ip, port)
                else:
                    li = line
                sl.append(li)

            newfiledata = '\n'.join(sl)
            f.seek(0, 0)
            try:
                f.write(newfiledata)
            except Exception, e:
                log.error('modify %s fail'%(docker_conf))
                return False

        except Exception,e:
            log.error('read %s fail'%(docker_conf))
            return False
        finally:
            f.close()

    except Exception, e:
        log.error('open docker conf fail') 
        return False
    return True


def confirm(msg):
    while True:
        try:
            choose = raw_input(msg+"Y/N").strip()[0].lower() 
        except (EOFError,KeyboardInterrupt,IndexError):
            choose = 'q'
        if choose == 'y':
            return True
        elif choose == 'n':
            return False
        elif choose == 'q':
            sys.exit(1)

       
def get_hostip():
    try:
        hostip = subprocess.check_output(["/bin/sh", "-c", 'ip route show | grep "192.168" | grep "metric" | grep -v "default" | awk \'{print $9}\'']).strip('\n')
        log.debug("hostip:"+hostip)
        return hostip
    except Exception,e:
        log.error("Can not get host ip:"+str(e))
        sys.exit(1)


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
    conf_db['registry_ip'] = config.get(section,'ip')
    conf_db['registry_port'] = config.get(section,'port')
    conf_db['registry_name'] = config.get(section,'name')
    conf_db['registry_store'] = config.get(section,'store')

    section = 'SERVER'
    conf_db['server_ip'] = config.get(section,'ip')
    conf_db['server_port'] = config.get(section, 'port')

    section = 'AGENT'
    conf_db['agent_ip'] = config.get(section, 'ip')

    return conf_db



def push_private_registry():
    pass

def install_registry():
    check_docker_running()
    parse_conf(conf_file)
    load_imagelists()
    add_insecure_registry()
    set_system_firewalld_selinux()
    run()
    push_private_registry()


def xtmain():
    script_dir_path =os.path.abspath(os.path.dirname(sys.argv[0]))
    config_path = script_dir_path+'/conf'
    zipped_path = script_dir_path+'/image_zipped.tar.gz'
    images_file = script_dir_path+'/imagelists'
    log.info("loading config from "+config_path)

    conf_db = parse_conf(config_path)

    for key in conf_db.keys():
       log.debug(key+':'+conf_db[key]) 

    while True:
        try:
            choose = raw_input("Install Private Registry,[Y]es/[N]o:").strip()[0].lower()
        except (EOFError,KeyboardInterrupt,IndexError):
            choose = 'q'
        if choose not in 'qyn':
            continue

        if choose == 'q':
            log.info("Quiting...")
            sys.exit(1) 
        elif choose == 'n':
            log.info("Cancel Private Registry install.")
            break
        else:
            log.info("Private Registry installing...")
            if not conf_db['registry_ip']:
                lr = Registry( port=conf_db['registry_port'],
                               name=conf_db['registry_name'],
                               store=conf_db['registry_store']
                            )
                if not lr.validate():
                    log.error('Invalid Registry Conf')
                    sys.exit(1)
                else:
                    lr.display()
            lr.check_env()
            lr.load_images(zipped_path, images_file)
            break                    

    #            install_registry()


def main():
    script_dir_path =os.path.abspath(os.path.dirname(sys.argv[0]))
    zipped_path = script_dir_path+'/image_zipped.tar.gz'
    images_file = script_dir_path+'/imagelists'
    #xtmain()
    #add_insecure_registry('192.168.4.2', '5050')
    rg = Remote_Registry('192.168.4.30')
    rg.display()
    rg.check_env()
    #rg.run_registry()
    rg.load_images(zipped_path, images_file)
    rg.run_registry()

if __name__ == '__main__':
    main()
