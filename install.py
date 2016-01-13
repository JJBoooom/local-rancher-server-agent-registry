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
    def __init__(self, user,password,ip, port='5000', name='MyPrivateRegistry', store='/var/lib/MyPrivateRegistry'):
        self.port = port
        self.name = name
        self.store = store
        self.ip = ip
        self.password = 'Cloudsoar123'

        if self.ip == get_hostip():
            self.local = True
        else:
            self.local = False
           

    def command_run(self, command):
        if self.local:
            with settings(warn_only=True):
                return local(command)
        else:
            env.host_string = "%s:%s"%(self.ip ,22) 
            env.password = self.password
            with settings(warn_only=True):
                return run(command)

    def move_file(self, src, dest):
        if self.local:
            return local('cp %s %s'%(src, dest))
        else:
            env.host_string = "%s:%s"%(self.ip ,22) 
            env.password = self.password
            return put(src, dest)

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
        try:
            result = self.command_run('which docker') 
            if result.failed:
                log.error('docker not intalled')
                raise MyException
            result = self.command_run('docker version')
            if result.failed and confirm('docker daemon isn\'t running, Try to start it?'):
                result = self.command_run('systemctl start docker') 
                if result.failed:
                    log.error('Can\'t start docker daemon')
                    raise MyException
                else:
                    log.error('cancel to start docker daemon')
                    raise MyException
            log.info('check docker enviroment success')
        except MyException:
            sys.exit(1) 



    def load_images(self, zipped_path, images_file):
        if not zipped_path or not images_file:
            log.debug('mising arguments')
            sys.exit(1)
        if not os.path.exists(zipped_path) or not os.path.exists(images_file):
            log.error('missing images zipped')
            sys.exit(1)

        try:
            tempdir = ''
            command = 'mktemp -d /tmp/zipped.XXXXXXX'
            result = self.command_run(command)
          
            if not result.failed:
                tempdir = result.stdout
            else:
                log.error('%s:create tempdir fail' % (self.ip))
                system.exit(1)

            result = self.move_file(zipped_path, tempdir)
            if result.failed:
                log.error('%s:moving zipped to temp dir fail' % (self.ip))
                raise MyException

            command = 'tar xvzf %s' % (os.path.join(tempdir,os.path.basename(zipped_path)))
            with cd(tempdir):
                result = self.command_run(command)

                if result.failed:
                    log.error("%s:untar fail"%(self.ip))
                    raise MyException

            zipped = (os.path.basename(zipped_path)).split('.')[0]
            temp_zipped = os.path.join(tempdir, zipped)
            command = 'ls %s' % (os.path.join(tempdir, zipped))
            result = self.command_run(command)
            if result.failed:
                log.error("%s:list file faile"%(self.ip))
                raise MyException
            else:
                command = 'ls'
                for tfile in result.stdout.split():
                    command = 'docker load --input %s/%s'%(temp_zipped, tfile)
                    result = self.command_run(command)
                    if result.failed:
                        log.error('%s:load %s fail'%(self.ip, tfile))
                        raise MyException
                   
        except MyException:
            command = 'rm -rf %s'%(tempdir)
            result = self.command_run(command)
            sys.exit(1)

    def add_registry():
        docker_conf = '/etc/sysconfig/docker'
        try:
            command = 'grep -e "^\s*#\+\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if not result.failed:
                content = 'INSECURE_REGISTRY=\'--insecure-registry %s:%s\''%(self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*#\+\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if not result.failed:
                    raise MyException
                else:
                    return 

            command = 'grep -e "^\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if not result.failed:
                content = result.stdout.strip().rstrip('\'')+' --insecure-registry %s:%s\'' % (self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return 

            content = 'INSECURE_REGISTRY= \'--insecure-registry %s:%s\'' %(self.registry_ip, self.registry_port)
            command = 'echo \"%s\" >> %s' % (content, docker_conf)
            result = self.command_run(command)
            if not result.failed:
                return 
            else:
                raise MyException

        except MyException:
            log.error('add registry fail')
            sys.exit(1) 

    def run_registry(self):
        try:
            result = self.command_run('docker  run -d --restart=always -p %s:5000 --name %s -v %s:/var/lib/registry registry:2' %( self.port, self.name, self.store))
            if result.failed:
                raise MyException
        except MyException:
            log.error('run registry fail')
            sys.exit(1)
            
    def push_private_registry(self, images_file):
        if not os.path.exists(images_file):
            log.error('image list file does not exist')
            sys.exit(1)

        try:
            f = open(images_file, 'r')
            try:
                try:
                    for eachline in f:
                        image = eachline.replace('docker.io','%s:%s'%(self.ip, self.port))
                        log.debug('image:%s'%image)
                        command = 'docker tag %s %s'%(eachline, image)
                        result = self.command_run(command)
                        if result.failed:
                            log.error('docker tag fail')
                            raise MyException
                        command = 'docker push %s'%(image)
                        result = self.command_run(command)
                        if result.failed:
                            raise MyException

                        return 
                except MyException:
                    log.error('push image fail')
                    sys.exit(1)
            except Exception, e:
                log.error('read file failed:' + str(e))
                sys.exit(1)
            finally:
                f.close()
        except Exception, e:
            log.error('open %s fail:'%(images_file)+str(e))
            sys.exit(1)

    def set_system_firewalld_selinux(self):
        command = 'systemctl stop firewalld'
        self.command_run(command)
        
        command = 'setenforce 0'
        self.command_run(command)
        
    def restart_docker(self):
        command = 'systemctl restart docker'
        result = self.command_run(command)
        if result.failed:
            sys.exit(1)
              
class RancherServer(object):
    def __init__(self, registry_ip, registry_port, password, ip, port='8080'):
        self.registry_ip = registry_ip
        self.registry_port = registry_port
        self.port = port
        self.ip = ip
        self.password = password

        if self.ip == get_hostip():
            self.local = True
        else:
            self.local = False

    def validate(self):
        return self.registry_ip != None and self.registry_port != None and self.ip != None and self.port != None 

    def command_run(self, command):
        if self.local:
            with settings(warn_only=True):
                return local(command)
        else:
            env.host_string = "%s:%s"%(self.ip ,22) 
            env.password = self.password
            with settings(warn_only=True):
                return run(command)

    def add_registry(self):
        env.host_string = "%s:%s"%(self.ip ,22) 
        env.password = self.password
        docker_conf = '/etc/sysconfig/docker'
        try:
            command = 'grep -e "^\s*#\+\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if not result.failed:
                content = 'INSECURE_REGISTRY=\'--insecure-registry %s:%s\''%(self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*#\+\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                log.info('command1:'+command)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return
                
            command = 'grep -e "^\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if not result.failed:
                content = result.stdout.strip().rstrip('\'')+' --insecure-registry %s:%s\'' % (self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return
            content = 'INSECURE_REGISTRY= \'--insecure-registry %s:%s\'' %(self.registry_ip, self.registry_port)
            command = 'echo \"%s\" >> %s' % (content, docker_conf)
            result = self.command_run(command)
            if result.failed:
                raise MyException
        except MyException:
            log.error('add Registry fail')
            sys.exit(1)

    def run_server(self):

        command = 'docker pull %s:%s/rancher/server'%(self.registry_ip, self.registry_port)
        try:
            result = self.command_run(command)
             if result.failed:
                log.error('pull image fail')
                raise MyException
            command = 'docker run -d --restart=always -p %s:8080 %s:%s/rancher/server' % (self.port, self.registry_ip, self.registry_port)
            result = self.command_run(command)
            if result.failed:
                log.error('run rancher server fail')
                raise MyException
        except MyException:
            sys.exit(1)

    def set_system_firewalld_selinux(self):

        command = 'systemctl stop firewalld'
        self.command_run(command)

        command = 'setenforce 0'
        self.command_run(command)

    def restart_docker(self):

        command = 'systemctl restart docker'
        result = self.command_run(command)
        if result.failed:
            sys.exit(1)

class RancherAgent(object):
    def __init__(self, registry_ip, registry_port, ip,password,command):
        self.registry_ip = registry_ip
        self.registry_port = registry_port
        self.ip = ip
        self.command = command
        self.password = password

        if self.ip == get_hostip():
            self.local = True
        else:
            self.local = False

    def command_run(self, command):
        if self.local:
            with settings(warn_only=True):
                return local(command)
        else:
            env.host_string = "%s:%s"%(self.ip ,22) 
            env.password = self.password
            with settings(warn_only=True):
                return run(command)

    def add_registry(self):

        env.host_string = "%s:%s"%(self.ip ,22) 
        env.password = self.password
        docker_conf = '/etc/sysconfig/docker'
        try:
            command = 'grep -e "^\s*#\+\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if not result.failed:
                content = 'INSECURE_REGISTRY=\'--insecure-registry %s:%s\''%(self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*#\+\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else
                    return

            command = 'grep -e "^\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if not result.failed:
                content = result.stdout.strip().rstrip('\'')+' --insecure-registry %s:%s\'' % (self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return

            content = 'INSECURE_REGISTRY= \'--insecure-registry %s:%s\'' %(self.registry_ip, self.registry_port)
            command = 'echo \"%s\" >> %s' % (content, docker_conf)
            result = self.command_run(command)
            if result.failed:
                raise MyException
            else:
                return
        except MyException:
            log.error('add registry fail')
            sys.exit(1)


    def restart_docker(self):
        command = 'systemctl restart docker'
        result = self.command_run(command)
        if result.failed:
            sys.exit(1)

    def run_agent(self):
        command = 'docker pull %s:%s/rancher/agent:v0.8.2'
        result = self.command_run(command)
        if result.failed():
            sys.exit(1)
            
        result = self.command_run(self.command) 
        if result.failed:
            log.error('run agent fail')
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


def list_registry():
    command = 'docker images | awk \'{print $1":"$2}\''

#获取所有镜像
def list_container(image):
    command = 'docker ps | awk \'{print $2}\''

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
    zipped_path = script_dir_path+'/images_zipped.tar.gz'
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
    zipped_path = script_dir_path+'/images_zipped.tar.gz'
    images_file = script_dir_path+'/imagelists'
    #xtmain()

    #add_insecure_registry('192.168.4.2', '5050')
    test='''
    rg = Remote_Registry('192.168.4.30')
    rg.display()
    rg.check_env()
    #rg.run_registry()
    rg.load_images(zipped_path, images_file)
    rg.set_system_firewalld_selinux()
    rg.run_registry()
    rg.add_registry()
    rg.push_private_registry(images_file)
    rs = Rserver('192.168.4.30', '5000', 'Cloudsoar123','192.168.4.29', port='8080')
    rs.add_registry()
    rs.restart_docker()
    rs.run_server()

    '''

    sr = Registry('root','Cloudsoar123','192.168.4.30', port='5000', name='MyPrivateRegistry', store='/var/lib/MyPrivateRegistry')
    sr.check_env()
    sr.load_images(zipped_path, images_file)
    sr.set_system_firewalld_selinux()
    sr.run_registry()
    sr.push_private_registry(images_file)
  
if __name__ == '__main__':
    main()
