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
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s - <%(levelname)s> - %(message)s')
log = logging.getLogger(__name__)

class MyException(Exception):
    pass

class ContainerException(Exception):
    pass
# Design my own exception for handing process?
class PullImageExcetion(ContainerException):
    pass

class FabricSupport:
    def __init__(self):
        pass
    def command_run(self,localflag, ip, password,command):
        if localflag:
            with settings(warn_only=True):
                return local(command)
        else:
            env.host_string = "%s:%s"%(ip ,22) 
            env.password = password
            with settings(warn_only=True):
                return run(command)

    def move_file(self,localflag,ip, password, src, dest):
        if localflag:
            return local('cp -rf %s %s'%(src, dest))
        else:
            env.host_string = "%s:%s"%(ip ,22) 
            env.password = password
            return put(src, dest)

class Registry(object):
    def __new__(cls, ip, port, password, name, store):
        if ip:
            return super(Registry, cls).__new__(cls)
        else:
            return None

    def __init__(self, ip, port, password, name, store):
        self.port = port
        self.name = name
        self.store = store
        self.ip = ip
        self.password = password
        
        if not self.port:
            self.port = '5000'
        if not self.name:
            self.name = 'MyPrivateRegistry'
        if not self.store:
            self.store = '/var/lib/MyPrivateRegistry'
        self.image='registry:2'

        if self.ip == get_hostip():
            self.local = True
        else:
            self.local = False
        
        if not self.password:
            content='Enter the %s\'s password:'%(self.ip)
            self.password = getpass.getpass(prompt=content)

    def validate(self):    
        return (self.ip  and self.port and 
            self.name and self.store and self.password)

    def check_running(self):
        command = 'docker ps | awk \'{print $2}\' | grep %s'%(self.image)
        log.debug(command)
        result = self.command_run(command)
        if result.failed:
            return False
        else:   
            return True

    def command_run(self, command):
        if self.local:
            with settings(
                hide('stdout','stderr'),
                warn_only=True
            ):
                return local(command)
        else:
            with settings(warn_only=True):
                env.host_string = "%s:%s"%(self.ip ,22) 
                env.password = self.password
                return run(command)

    def move_file(self, src, dest):
        if self.local:
            return local('cp -rf %s %s'%(src, dest))
        else:
            env.host_string = "%s:%s"%(self.ip ,22) 
            env.password = self.password
            return put(src, dest)

    def check_host(self):
        if self.local:
            return True
        else:
            command = 'ping %s -c 3'%(self.ip)
            with settings(warn_only=True):
                result = local(command)
            if result.failed:
                log.error('\'%s\' connection not reach'%(self.ip))
                return False
            else:
            #purpose: check password. need accurate method
                command = 'ls'
                result = self.command_run(command)
                if result.failed:  
                    log.error('connect to \'%s\' fail'%self.ip)
                    return False
            return True
    #缺少端口,镜像名以及共享卷合法性认证

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
            if result.failed:
                if confirm('docker daemon isn\'t running, Try to start it?'):
                    result = self.command_run('systemctl start docker') 
                    if result.failed:
                        log.error('Can\'t start docker daemon')
                        raise MyException
                else:
                    log.error('cancel to start docker daemon')
                    raise MyException
            else:
                log.info('check docker enviroment success')
                return True
        except MyException:
            return False

    def load_images(self, zipped_path, images_file):
        if not zipped_path or not images_file:
            log.debug('mising arguments')
            sys.exit(1)
        if not os.path.exists(zipped_path) or not os.path.exists(images_file):
            log.error('missing images zipped')
            sys.exit(1)

        log.debug('start to load images..')
        command = 'docker images | awk \'{print $1":"$2}\''
        result = self.command_run(command)
        if result.failed:
            log.error('get images failed')
            sys.exit(1)
        else:
            dockerimages = result.stdout.strip().split('\r\n')
            for i in dockerimages:
                print i
            try:
                dockerimages.remove("REPOSITORY:TAG")
            except ValueError:
                pass
            log.debug('..................')
            for i in dockerimages:
                print i
            
           
            if dockerimages: 
                log.debug('check if all image exist in local')
                try:
                    f = open(images_file, 'r')
                    all_match_flag = True
                    for eachline in f:
                        li = eachline.strip()
                        match_flag = False
                        for j in dockerimages:
                            if j == li:
                                match_flag = True
                                all_match_flag = False
                                break
                        if match_flag:
                            continue
                        log.info('all image exists, skip loading images') 
                        return
                except Exception, e:
                    log.error('open %s fail:'%(images_file)+str(e))
                    sys.exit(1)
                finally:
                    f.close()
            else:
                log.debug('missing  image,start to load image')

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
            log.errot('load image fail')
            sys.exit(1)
        finally:
            command = 'rm -rf %s'%(tempdir)
            result = self.command_run(command)

    def add_registry(self):
        docker_conf = '/etc/sysconfig/docker'
        try:
            command = 'grep -e "^\s*#\+\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                content = 'INSECURE_REGISTRY=\'--insecure-registry %s:%s\''%(self.ip, self.port)
                command = 'sed -i "s/^\s*#\+\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return 

            command = 'grep -e "^\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                content = result.stdout.strip().rstrip('\'')+' --insecure-registry %s:%s\'' % (self.ip, self.port)
                command = 'sed -i "s/^\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return 

            content = 'INSECURE_REGISTRY= \'--insecure-registry %s:%s\'' %(self.ip, self.port)
            command = 'echo \"%s\" >> %s' % (content, docker_conf)
            result = self.command_run(command)
            if result.succeeded:
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

        command = 'docker images | awk \'{print $1":"$2}\''
        result = self.command_run(command)
        if result.failed:
            log.error('get images failed')
            sys.exit(1)
        else:
            dockerimages = result.stdout.strip().split('\r\n')
            log.error('docker images:%s'%(repr(dockerimages)))

        try:
            f = open(images_file, 'r')
            try:
                try:
                #do some check, skip alrealy exist image
                    for eachline in f:
                        exist_flag = False
                        li = eachline.strip()
                        if li.startswith('#') or not li:
                            continue

                        newimage = li.replace('docker.io','%s:%s'%(self.ip, self.port))
                        tag_image_exist = False
                        for j in dockerimages:
                            if j == newimage:
                                log.info('tag image found,skip')
                                tag_image_exist = True
                                break
                            
                        if not tag_image_exist:
                            command = 'docker tag %s %s'%(li, newimage)
                            result = self.command_run(command)
                            if result.failed:
                                log.error('docker tag fail')
                                raise MyException
                        command = 'docker push %s'%(newimage)
                        result = self.command_run(command)
                        if result.failed:
                            raise MyException
                #need some cleanup?
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
    def __new__(cls, registry_ip, registry_port, registry_password, ip, port, password):
        if ip and registry_ip and registry_port:
            return super(RancherServer, cls).__new__(cls)
        else:
            return None

    def __init__(self, registry_ip, registry_port, registry_password, ip, port, password):
        self.registry_ip = registry_ip
        self.registry_port = registry_port
        self.registry_password = registry_password
        self.port = port
        self.ip = ip
        self.password = password
        self.image='rancher/server:latest'

        if self.ip == get_hostip():
            self.local = True
        else:
            self.local = False
        
        if not self.port:  
            self.port = '8080'

        if not self.registry_password:
            content='Enter Registry %s\'s password:'%(self.registry_ip)
            self.registry_password = getpass.getpass(prompt=content)

        if not self.password:
            content='Enter Rancher Server %s\'s password:'%(self.ip)
            self.password = getpass.getpass(prompt=content)

    def validate(self):
        return self.registry_ip != None and self.registry_port != None and self.ip != None and self.port != None 

    def check_env(self):
        try:
            result = self.command_run('which docker') 
            if result.failed:
                log.error('docker not intalled')
                raise MyException

            result = self.command_run('docker version')
            if result.failed:
                if confirm('docker daemon isn\'t running, Try to start it?'):
                    result = self.command_run('systemctl start docker') 
                    if result.failed:
                        log.error('Can\'t start docker daemon')
                        raise MyException
                else:
                    log.error('cancel to start docker daemon')
                    raise MyException
            else:
                log.info('check docker enviroment success')
                return True
        except MyException:
            return False

    def check_host(self):
        if self.local:
            return True
        else:
            command = 'ping %s -c 3'%(self.ip)
            with settings(warn_only=True):
                result = local(command)
            if result.failed:
                log.error('\'%s\' connection not reach'%(self.ip))
                return False
            else:
            #purpose: check password. need accurate method
            #paramiko will be better way
                command = 'ls'
                result = self.command_run(command)
                if result.failed:  
                    log.error('connect to \'%s\' fail'%self.ip)
                    return False
            return True

    def check_registry(self):
        #command = 'docker ps | awk \'{print $2}\' | grep %s:%s/registry:2'%(self.registry_ip, self.registry_port)
        command = 'docker ps | awk \'{print $2}\' | grep registry:2'
        if self.registry_ip == get_hostip():
            with settings(warn_only=True):
                result = local(command)
                if result.failed:
                    log.error('registry is not running')
                    return False
                else:
                    return True
        else:
            env.host_string = "%s:%s"%(self.registry_ip ,22) 
            env.password = self.registry_password
            with settings(warn_only=True):
                result = run(command)
                if result.failed:
                    log.error('registry is not running')
                    return False
                else:
                    return True

    def check_running(self):
        command = 'docker ps | awk \'{print $2}\' | grep %s:%s/%s'%(self.registry_ip, self.registry_port,self.image)
        result = self.command_run(command)
        if result.failed:
            return False
        else:   
            return True

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
            if result.succeeded:
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
            if result.succeeded:
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

    def pull_image(self):
        command = 'docker images | awk \'{print $1":"$2}\'' 
        result = self.command_run(command)
        if result.failed:
            logging.warn('can\'t get docker images')
        else:
            rancher_server_image = 'docker.io/%s'%(self.image)
            for image in result.stdout.strip():
                if image == rancher_server_image:
                    log.debug('image[%s] exists, skipping pull'%(rancher_server_image))
                    return

        command = 'docker pull %s:%s/%s'%(self.registry_ip, self.registry_port, self.image)
        result = self.command_run(command)
        if result.failed:
            sys.exit(1)

        #need to add check for images.existence
        command = 'docker tag %s:%s/%s docker.io/%s'%(self.registry_ip, self.registry_port, self.image, self.image)
        result = self.command_run(command)
        if result.failed:
            sys.exit(1)

    def run_server(self):
        command = 'docker pull %s:%s/%s'%(self.registry_ip, self.registry_port, self.image)
        try:
            result = self.command_run(command)
            if result.failed:
                log.error('pull image fail')
                raise MyException
            command = 'docker run -d --restart=always -p %s:8080 %s:%s/%s' % (self.port, self.registry_ip, self.registry_port, self.image)
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

#docker run -d -e ENV_DOCKER_REGISTRY_HOST=192.168.4.32 -e ENV_DOCKER_REGISTRY_PORT=5000 -e ENV_MODE_BROWSE_ONLY=false -p 9988:80 konradkleine/docker-registry-frontend:v2
class RegistryFrontend(object):
    def __new__(cls, ip, password, registry_ip, registry_port, registry_password, port, name):
        if ip and registry_ip and registry_port:
            return super(RegistryFrontend, cls).__new__(cls)
        else:
            return None

    def __init__(self, ip, password,registry_ip, registry_port, registry_password, port, name):
        self.ip = ip
        self.password = password
        self.registry_ip = registry_ip
        self.registry_port = registry_port
        self.registry_password = registry_password
        self.port = port
        self.name = name
        self.image = 'konradkleine/docker-registry-frontend:v2'

        if self.ip == get_hostip():
            self.local = True 
        else:
            self.local = False 

        if not self.password:
            content='Enter registry frontend %s\'s password:'%(self.ip)
            self.password = getpass.getpass(prompt=content)
       
        if not self.registry_password:
            content='Enter registry %s\'s password:'%(self.registry_ip)
            self.registry_password = getpass.getpass(prompt=content)

    def check_env(self):
        try:
            result = self.command_run('which docker') 
            if result.failed:
                log.error('docker not intalled')
                raise MyException
            result = self.command_run('docker version')
            if result.failed:
                if confirm('docker daemon isn\'t running, Try to start it?'):
                    result = self.command_run('systemctl start docker') 
                    if result.failed:
                        log.error('Can\'t start docker daemon')
                        raise MyException
                else:
                    log.error('cancel to start docker daemon')
                    raise MyException
            else:
                log.info('check docker enviroment success')
                return True
        except MyException:
            return False
    #for pull image and registry must run 
    def check_registry(self):
        #command = 'docker ps | awk \'{print $2}\' | grep %s:%s/registry:2'%(self.registry_ip, self.registry_port)
        command = 'docker ps | awk \'{print $2}\' | grep registry:2'
        if self.registry_ip == get_hostip():
            with settings(warn_only=True):
                result = local(command)
                if result.failed:
                    log.error('registry is not running')
                    return False
                else:
                    return True
        else:
            env.host_string = "%s:%s"%(self.registry_ip ,22) 
            env.password = self.registry_password
            with settings(warn_only=True):
                result = run(command)
                if result.failed:
                    log.error('registry is not running')
                    return False
                else:
                    return True

    def check_host(self):
        if self.local:
            return True
        else:
            command = 'ping %s -c 3'%(self.ip)
            with settings(warn_only=True):
                result = local(command)
            if result.failed:
                log.error('\'%s\' connection not reach'%(self.ip))
                return False
            else:
            #purpose: check password. need accurate method
                command = 'ls'
                result = self.command_run(command)
                if result.failed:  
                    log.error('connect to \'%s\' fail'%self.ip)
                    return False
                else:
                    return True
    #check container is running?
    def check_running(self):
        command = 'docker ps | awk \'{print $2}\' | grep %s'%(self.image)
        result = self.command_run(command)
        if result.failed:
            return False
        else:   
            logging.info('web container is running...')
            return True
    
    def command_run(self, command):
        if self.local:
            with settings(warn_only=True):
                return local(command)
        else:
            env.host_string = "%s:%s"%(self.ip ,22) 
            env.password = self.password
            with settings(warn_only=True):
                return run(command)
    
    def pull_image(self):

        command = 'docker images | awk \'{print $1":"$2}\'' 
        result = self.command_run(command)
        if result.failed:
            logging.warn('can\'t get docker images')
        else:
            frontend_image = 'docker.io/%s'%(self.image)
            dockerimages = result.stdout.strip().split('\r\n')
            for image in dockerimages:
                if image == frontend_image:
                    log.debug('image[%s] exists, skipping pull'%(frontend_image))
                    return
        #增加镜像是否存在的判断
        command = 'docker pull %s:%s/%s'%(self.registry_ip, self.registry_port, self.image)
        result = self.command_run(command)
        if result.failed:
            sys.exit(1)

        #need to add check for images.existence
        tag_image = 'docker.io/%s'%(self.image)
        for j in dockerimages:
            if j == self.image:
                log.info('%s exist, skip tag'%(self.image))
                return 
            else:
                command = 'docker tag %s:%s/%s docker.io/%s'%(self.registry_ip, self.registry_port, self.image, self.image)
                result = self.command_run(command)
                if result.failed:
                    sys.exit(1)

    def restart_docker(self):
        command = 'systemctl restart docker'
        result = self.command_run(command)
        if result.failed:
            sys.exit(1)

    def add_registry(self):
        docker_conf = '/etc/sysconfig/docker'
        try:
            command = 'grep -e "^\s*#\+\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                content = 'INSECURE_REGISTRY=\'--insecure-registry %s:%s\''%(self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*#\+\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return 

            command = 'grep -e "^\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                content = result.stdout.strip().rstrip('\'')+' --insecure-registry %s:%s\'' % (self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return 

            content = 'INSECURE_REGISTRY= \'--insecure-registry %s:%s\'' %(self.self.registry_ip, self.registry_port)
            command = 'echo \"%s\" >> %s' % (content, docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                return 
            else:
                raise MyException

        except MyException:
            log.error('add registry fail')
            sys.exit(1) 

        self.restart_docker()


    def run_container(self):
        command = 'docker run -d  --restart=always -e ENV_DOCKER_REGISTRY_HOST=%s -e ENV_DOCKER_REGISTRY_PORT=%s -e ENV_MODE_BROWSE_ONLY=false -p %s:80 --name %s konradkleine/docker-registry-frontend:v2'%(self.registry_ip, self.registry_port, self.port, self.name)
        result = self.command_run(command)
        if result.failed:
            log.error('web server container run fail')
            sys.exit(1)
        else:
            log.info('Web server container start')
            
    def set_system_firewalld_selinux(self):
        command = 'systemctl stop firewalld'
        self.command_run(command)
        
        command = 'setenforce 0'
#need to find some way to check rancher server is running?
# http request to website? good way but how?
class RancherAgent(object):
    def __new__(cls, registry_ip, registry_port, registry_password, server_ip, server_password, ip, password, add_host_command):
        if ip and registry_ip and registry_port and server_ip and add_host_command:
            return super(RancherAgent, cls).__new__(cls)
        else:
            return None
    def __init__(self, registry_ip, registry_port, registry_password, server_ip, server_password, ip,  password, add_host_command):
        self.registry_ip = registry_ip
        self.registry_port = registry_port
        self.registry_password = registry_password
        self.server_ip = server_ip
        self.server_password = server_password
        self.ip = ip
        self.password = password
        self.command = add_host_command
        self.image = 'rancher/agent:v0.8.2'

        if self.ip == get_hostip():
            self.local = True
        else:
            self.local = False

        if not self.server_password:
            content='Enter Rancher Server %s\'s password:'%(self.server_ip)
            self.password = getpass.getpass(prompt='Enter the Root\'s password in %s'%(self.ip))

        if not self.registry_password:
            content='Enter Registry %s\'s password:'%(self.registry_ip)
            self.password = getpass.getpass(prompt=content)

        if not self.password:
            content='Enter Agent %s\'s password:'%(self.ip)
            self.password = getpass.getpass(content)

    def check_host(self):
        if self.local:
            return True
        else:
            #
            command = 'ping %s -c 3'%(self.ip)
            with settings(warn_only=True):
                result = local(command)
            if result.failed:
                log.error('\'%s\' connection not reach'%(self.ip))
                return False
            else:
            #purpose: check password. need accurate method
                command = 'ls'
                result = self.command_run(command)
                if result.failed:  
                    log.error('connect to \'%s\' fail'%self.ip)
                    return False
            return True

    def check_registry(self):
     #   command = 'docker ps | awk \'{print $2}\' | grep %s:%s/registry:2'%(self.registry_ip, self.registry_port)
        command = 'docker ps | awk \'{print $2}\' | grep registry:2'
        if self.registry_ip == get_hostip():
            with settings(warn_only=True):
                result = local(command)
                if result.failed:
                    log.error('registry is not running')
                    return False
                else:
                    return True
        else:
            env.host_string = "%s:%s"%(self.registry_ip ,22) 
            env.password = self.registry_password
            with settings(warn_only=True):
                result = run(command)
                if result.failed:
                    log.error('registry is not running')
                    return False
                else:
                    return True

    def check_rancher_server(self):
        command = 'docker ps | awk \'{print $2}\' | grep %s:%s/rancher/server:latest'%(self.registry_ip, self.registry_port)
        if self.server_ip == get_hostip():
            with settings(warn_only=True):
                result = local(command)
                if result.failed:
                    log.error('rancher server is not running')
                    return False
                else:
                    return True
        else:
            env.host_string = "%s:%s"%(self.server_ip ,22) 
            env.password = self.server_password
            with settings(warn_only=True):
                result = run(command)
                if result.failed:
                    log.error('rancher server is not running')
                    return False
                else:
                    return True


    def check_running(self):
        command = 'docker ps | awk \'{print $2}\' | grep %s'%(self.image)
        result = self.command_run(command)
        if result.failed:
            return False
        else:
            return True

    def command_run(self, command):
        if self.local:
            with settings(hide('stdout,stderr'), warn_only=True):
                return local(command)
        else:
            env.host_string = "%s:%s"%(self.ip ,22) 
            env.password = self.password
            with settings(hide('stdout','stderr'), warn_only=True):
                return run(command)

    def add_registry(self):
        env.host_string = "%s:%s"%(self.ip ,22) 
        env.password = self.password
        docker_conf = '/etc/sysconfig/docker'
        try:
            command = 'grep -e "^\s*#\+\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                content = 'INSECURE_REGISTRY=\'--insecure-registry %s:%s\''%(self.registry_ip, self.registry_port)
                command = 'sed -i "s/^\s*#\+\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException
                else:
                    return

            command = 'grep -e "^\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if result.succeeded:
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

    def pull_image(self):
        command = 'docker images | awk \'{print $1":"$2}\'' 
        result = self.command_run(command)
        if result.failed:
            logging.warn('can\'t get docker images')
            sys.exit(1)
        else:
            agent_image = 'docker.io/%s'%(self.image)
            agent_instance_image = 'docker.io/agent-instance:v0.6.0'
            dockerimages = result.stdout.strip().split('\r\n')
            log.info('agent_image:%s'%repr(agent_image))
            log.info('agent_instance_image:%s'%repr(agent_instance_image))
            e_agent = False
            e_instance = False
            t_agent_instance = False
            t_agent = False
            for i in dockerimages:
                log.info('image:%s'%repr(i))
            for image in dockerimages:
                if image == agent_image:
                    t_agent = True
                    continue
                if  image == agent_instance_image:
                    t_agent_instance = True
                    continue
                r_agent = agent_image.replace('docker.io','%s:%s'%(self.registry_ip, self.registry_port))
                log.info('r_agent:%s'%(r_agent))
                if image == r_agent:
                    e_agent = True
                    continue

                r_instance = agent_instance_image.replace('docker.io','%s:%s'%(self.registry_ip, self.registry_port))
                if image == r_instance:
                    e_instance = True

            if not e_instance:
                command = 'docker pull %s:%s/rancher/agent-instance:v0.6.0'%(self.registry_ip, self.registry_port)
                result = self.command_run(command)
                if result.failed:
                    sys.exit(1)

            if not t_agent_instance:
                command = 'docker tag %s:%s/rancher/agent-instance:v0.6.0 docker.io/rancher/agent:v0.8.2'%(self.registry_ip, self.registry_port)
                result = self.command_run(command)
                if result.failed:
                    sys.exit(1)

            if not e_agent:
                command = 'docker pull %s:%s/rancher/agent:v0.8.2'%(self.registry_ip, self.registry_port)
                result = self.command_run(command)
                if result.failed:
                    sys.exit(1)
            
            if not t_agent:
                command = 'docker tag %s:%s/rancher/agent:v0.8.2 docker.io/rancher/agent:v0.8.2'%(self.registry_ip, self.registry_port)
                result = self.command_run(command)
                if result.failed:
                    sys.exit(1)

    def run_agent(self):
        result = self.command_run(self.command) 
        if result.failed:
            log.error('run agent fail')
            sys.exit(1)
        
    def set_system_firewalld_selinux(self):
        command = 'systemctl stop firewalld'
        self.command_run(command)
        
        command = 'setenforce 0'
           
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
        else:
            pass
       
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
        if options == 'rancher-server-command':
            if not config.get(section, options):
                log.error('Must set rancher-server-command option, get it from rancher server web page > ADD HOST PAGE')
                sys.exit(1)
            agents_conf[options]= clean_str(config.get(section, options))
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

def list_registry():
    command = 'docker images | awk \'{print $1":"$2}\''

#获取所有镜像
def list_container(image):
    command = 'docker ps | awk \'{print $2}\''


def setup_agent(conf_db, agents_conf, ip):
    agent = RancherAgent(conf_db['registry_ip'], 
                         conf_db['registry_port'], 
                         conf_db['registry_password'],
                         conf_db['server_ip'],
                         conf_db['server_password'],
                         ip,
                         agents_conf[ip],
                         agents_conf['rancher-server-command']
                         )
    #def __new__(cls, registry_ip, registry_port, registry_password, server_ip, server_password, ip, password, command):
    if not agent.check_host():
        log.error('can\'t connect to host')
        return
    if agent.check_running():
        log.error('Agent is running')
        return
    if not agent.check_rancher_server():
        log.error('rancher server aren\'t running')
        return
    if not agent.check_registry():
        log.error('registry aren\'t running')
        return
    agent.add_registry()
    agent.restart_docker()
    agent.pull_image()
    agent.run_agent()


def main():
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
            rg = Registry( port=conf_db['registry_port'],
                           ip=conf_db['registry_ip'],
                           store=conf_db['registry_store'],
                           name=conf_db['registry_name'],
                           password=conf_db['registry_password'],
                        )
            if not rg:
                log.error('Invalid Registry Conf')
                sys.exit(1)
           # rg.validate()
           # rg.display()
            if not rg.check_host():
                log.error('Can\'t connect to host[%s]'%(rg.ip))
                sys.exit(1)
            if not rg.check_env():
                log.error('docker\'s environment not sufficient')
                sys.exit(1)
            
            rg.load_images(zipped_path, images_file)
            rg.set_system_firewalld_selinux()
            if not rg.check_running():
                log.info('start to run registry ')
                rg.run_registry()
                rg.add_registry()
                rg.push_private_registry(images_file)
            else:
                log.info('registry is running, push new images')
                rg.push_private_registry(images_file)
            break                    


    while True:
        try:
            choose = raw_input("Install Rancher Server,[Y]es/[N]o:").strip()[0].lower()
        except (EOFError,KeyboardInterrupt,IndexError):
            choose = 'q'
        if choose not in 'qyn':
            continue

        if choose == 'q':
            log.info("Quiting...")
            sys.exit(1) 
        elif choose == 'n':
            log.info("Cancel Rancher Server install.")
            break
        else:
            log.info("Rancher Server installing...")

            rs = RancherServer(
                registry_ip=conf_db['registry_ip'],
                registry_port=conf_db['registry_port'], 
                registry_password=conf_db['registry_password'], 
                ip=conf_db['server_ip'], 
                port=conf_db['server_port'],
                password=conf_db['server_password'])
            if not rs:
                log.error('Rancher Server Invalid conf')
                sys.exit(1)
            if not rs.check_host():
                log.error('can\'t connect to Host')
                sys.exit(1)
            if not rs.check_env():
                log.error('docker enviroment not sufficient')
                sys.exit(1)
            if not rs.check_registry():
                log.error('registry is not running')
                sys.exit(1)
            if rs.check_running():
                log.info('rancher server is running')
                break
            rs.add_registry()
            rs.restart_docker()
            rs.run_server()
            break

    while True:
        try:
            choose = raw_input("Instal Registry Frontend,[Y]es/[N]o:").strip()[0].lower()
        except (EOFError,KeyboardInterrupt,IndexError):
            choose = 'q'
        if choose not in 'qyn':
            continue

        if choose == 'q':
            log.info("Quiting...")
            sys.exit(1) 
        elif choose == 'n':
            log.info("Cancel Registry Frontend install.")
            break
        else:
            log.info("Registry Frontend installing...")
            
            rf = RegistryFrontend(conf_db['registry_frontend_ip'],
                            conf_db['registry_frontend_password'],
                            conf_db['registry_ip'],
                            conf_db['registry_port'],
                            conf_db['registry_password'],
                            conf_db['registry_frontend_port'],
                            conf_db['registry_frontend_name'])
            if not rf:
                log.error('Invalid arguments')
                sys.exit(1)
            else:
                if not rf.check_host():
                    log.error('can\'t connect to host')
                    sys.exit(1)
                if not rf.check_env():
                    log.error('docker enviroment not sufficient')
                    sys.exit(1)
                if rf.check_running():
                    log.info('registry frontend is running')
                    break
                if not rf.check_registry():
                    log.error('registry is not running')
                    sys.exit(1)
                rf.add_registry()
                rf.pull_image()
                rf.run_container()

                log.info('registry frontend starts')
                break

    while True:
        try:
            choose = raw_input("Install Rancher Agents,[Y]es/[N]o:").strip()[0].lower()
        except (EOFError,KeyboardInterrupt,IndexError):
            choose = 'q'
        if choose not in 'qyn':
            continue

        if choose == 'q':
            log.info("Quiting...")
            sys.exit(1) 
        elif choose == 'n':
            log.info("Cancel Rancher Agents install.")
            break
        else:
            log.info("Rancher Agent installing...")
    
            agents_conf = parse_agent_conf(config_path)

            threads = []
            for ip in agents_conf.keys():
                if ip != 'rancher-server-command':
                    t = threading.Thread(target=setup_agent, args=(conf_db, agents_conf, ip, ))
                    t.start()
                    threads.append(t)

            for t in threads:
                t.join()
            log.info('Adding agent finish')
            break

        
if __name__ == '__main__':
    main()

   
