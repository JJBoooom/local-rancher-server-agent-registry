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
from docker import Client
from fabric.api import *
from fabric import exceptions
import fabric

import time
from Crypto.Cipher import AES
import base64
import getopt

logging.basicConfig(level=logging.INFO, format='%(asctime)s - <%(levelname)s> - %(message)s')
log = logging.getLogger(__name__)

#for encrpyt
_secret_key='1234567890123456'
DEBUG=False

class ContainerParameterError(Exception):
    pass

class MyException(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg
class FiveTimeWrongPWError(MyException):
    pass
        
class LoadImageError(Exception):
    pass

class ContainerRunError(MyException):
    def __init__(self, command):
        self.command = command
    def __str__(self):
        return 'Docker command\'%s\' run fail'%(self.command)


class DockerListImageError(MyException):
    pass

class DockerPullImageError(MyException):
    pass


class PortUsedError(MyException):
    def __init__(self, msg, port):
        MyException.__init__(self,msg)
        self.port = port
    def __str__(self):
        return '([%s]:%s)'%(self.port, self.msg)
        

class FabricSupport:
    def __init__(self,ip, password = None):
        self.ip = ip
        self.password = password

    def command_run(self, localflag ,command):
        log.debug('command:%s'%command)

        if localflag:
            with settings(hide('warnings','stdout','stderr','running',),warn_only=True):
                return local(command, capture=True)
        else:
            try:
                env.host_string = "%s:%s"%(self.ip ,22) 
                env.password = self.password
                with settings(hide('warnings','stdout','stderr','running',),warn_only=True):
                    return run(command)
            except exceptions.NetworkError,e:
                raise MyException(str(e))
            

    def move_file(self, localflag, src, dest):
        log.debug('move file:%s---->%s'%(src, dest))
        if localflag:
            with settings(hide('warnings','stdout','stderr','running',),warn_only=True):
                return local('cp -rf %s %s'%(src, dest),capture=True)
        else:
            try:
                env.host_string = "%s:%s"%(self.ip ,22) 
                env.password = self.password
                with settings(hide('warnings','stdout','stderr','running',),warn_only=True):
                    return put(src, dest)
            except exceptions.NetworkError,e:
                raise MyException(str(e))

class Container(FabricSupport):

    def __init__(self, ip, image, port, password=None):

        if not ip or not image or not port:
            raise ContainerParameterError

        FabricSupport.__init__(self, ip, password)
        self.image = image
        self.port = port
        self.password = password
            
#        if not self.password:
#            content='Enter the %s\'s password:'%(self.ip)
#            self.password = getpass.getpass(prompt=content)

        if self.ip == get_hostip():
            self.local = True
        else:
            self.local = False 


    def command_run(self, command):
        return FabricSupport.command_run(self, self.local, command)

    def move_file(self, src, dest):
        return FabricSupport.move_file(self, self.local, src,dest)

    def check_host(self):
        if self.local:
            return
        else:
        #    return True
            log.debug('start to check host')
            i = 6 
            while i:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.ip, 22, "root",self.password)
                    log.info('check host success')
                    return 
                except paramiko.ssh_exception.AuthenticationException, e: 
                    
                    log.error(e)
                    i = i-1
                    if i == 0:
                        raise MyException("Over 5 times input wrong password...")
                    content = "please input \'%s\' correct password:"%(self.ip)
                    self.password = getpass.getpass(content)

                except Exception, e:
                    raise MyException(str(e)) 
                finally:
                    ssh.close()
            raise MyException("Over 5 times input wrong password...")


    def check_env(self):
        result = self.command_run('which docker') 
        if result.failed:
            raise MyException('docker doesn\'t install')
        result = self.command_run('docker version')
        if result.failed:
            if confirm('docker daemon isn\'t running, Try to start it?'):
                result = self.command_run('systemctl start docker') 
                if result.failed:
                    raise MyException('Can\'t start docker daemon')
            else:
                raise MyException('cancel to start docker daemon')
        else:
            log.debug('docker version:%s'%(result.stdout))
            log.info('check docker enviroment success')

    def check_running(self):

        command = 'docker ps | awk \'{print $2}\' | grep %s'%(self.image)
        log.debug(command)
        result = self.command_run(command)
        if result.failed:
            return False
        else:
            log.debug("running:%s"%result.stdout)
            return True


    def check_port_used(self):
        if int(self.port) < 0 or int(self.port) > 65535:
            raise MyException('Invalid port:%s'%self.port)
        command = 'netstat -talnp | grep %s'%(self.port)
        result = self.command_run(command)
        if result.failed:
            log.info('Port[%s] is available'%(self.port))
        else:
            log.debug('port is used:%s'%(result.stdout))
            raise  PortUsedError('port is used', self.port)

    def add_registry(self, registry_ip, registry_port):
        docker_conf = '/etc/sysconfig/docker'
        command = 'grep -e "^\s*INSECURE_REGISTRY.*--insecure-registry\s*%s:%s" %s'%(registry_ip, registry_port, docker_conf)
        result = self.command_run(command)
        if result.succeeded:
            log.debug('add_registry:%s'%(result.stdout))
            log.info('add private registry success')
            return
        else:
            pass

        try:
            command = 'grep -e "^\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                content = result.stdout.strip().rstrip('\'')+' --insecure-registry %s:%s\'' % (registry_ip, registry_port)
                log.debug('2content:%s'%content)
                command = 'sed -i "s/^\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException('set docker private registry conf failed')
                else:
                    log.info('add private registry success')
                    return 

            command = 'grep -e "^\s*#\+\s*INSECURE_REGISTRY" %s'%(docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                content = 'INSECURE_REGISTRY=\'--insecure-registry %s:%s\''%(registry_ip, registry_port)
                log.debug('content:%s'%content)
                command = 'sed -i "s/^\s*#\+\s*INSECURE_REGISTRY.*/%s/g" %s' %(content, docker_conf)
                result = self.command_run(command)
                if result.failed:
                    raise MyException('set docker private registry conf failed')
                else:
                    log.info('add private registry success')
                    return 

            content = 'INSECURE_REGISTRY= \'--insecure-registry %s:%s\'' %(registry_ip, registry_port)
            log.debug('3content:%s'%content)
            command = 'echo \"%s\" >> %s' % (content, docker_conf)
            result = self.command_run(command)
            if result.succeeded:
                log.info('add private registry success')
                return 
            else:
                raise MyException('set docker private registry conf failed')

        except MyException:
            raise MyException('add registry fail')

    def set_system_firewalld_selinux(self):
#        command = 'systemctl stop firewalld'
#        self.command_run(command)
        
        command = 'setenforce 0'
        self.command_run(command)
        
    def restart_docker(self):
        command = 'systemctl restart docker'
        result = self.command_run(command) 
        if result.failed:
            log.info('restart docker fail....')
            sys.exit(1)
              


class Registry(Container):
    def __init__(self, ip, port, store, password=None, name=None):
        image = 'registry:2'
        Container.__init__(self, ip, image, port, password)
        self.store = store
        self.name = name
       
        if not self.store:
            self.store = '/var/lib/MyPrivateRegistry'


    #def __init__(self, ip, image, port,password=None):
    def load_images(self, zipped_path, images_file):
        if not os.path.exists(zipped_path):
            raise MyException('%s not exist'%(zipped_path))
        
        if not os.path.exists(images_file):
            raise MyException('%s not exist'%(images_file))

        command = 'docker images | awk \'{print $1":"$2}\''
        result = self.command_run(command)
        if result.failed:
            raise MyException('get images failed')
        else:
            if self.local:
                dockerimages = result.stdout.strip().split('\n')
            else:
                dockerimages = result.stdout.strip().split('\r\n')

            try:
                dockerimages.remove("REPOSITORY:TAG")
            except ValueError:
                pass
        #    deprecated='''
            if dockerimages: 
                log.info('check if all image exist in local')
                try:

                    f = open(images_file, 'r')
                    all_match_flag = True
                    for eachline in f:
                        li = eachline.strip()
                        if li.startswith('#') or not li:
                            continue
                        log.debug('Imagelist:%s'%li)
                        match_flag = False
                        for j in dockerimages:
                            if j == li:
                                match_flag = True
                                break
                        if match_flag:
                            continue
                        log.info('image %s not exist'%(li))
                        all_match_flag = False
                        break

                    if all_match_flag:
                        log.info('all image exists, skip loading images') 
                        return
                    else:
                        log.info('some images don\'t exist in local,start to load image')
                except Exception, e:
                    log.error('open %s fail:'%(images_file)+str(e))
                    sys.exit(1)
                finally:
                    f.close()
            else:
                log.info('some images don\'t exist in local,start to load image')
                
        log.info('start to upload local image tar package, it will lasts a few minutes, please wait in patience....')
        try:
            tempdir = ''
            command = 'mktemp -d /tmp/zipped.XXXXXXX'
          #  command = 'mktemp -d /var/test/zipped.XXXXXXX'
            result = self.command_run(command)
          
            if not result.failed:
                tempdir = result.stdout
            else:
                LoadImageError('%s:create tempdir fail' % (self.ip))

            result = self.move_file(zipped_path, tempdir)
            if result.failed:
                raise LoadImageError('%s:moving zipped to temp dir fail' % (self.ip))
            log.info('upload image tar package successfully, now try to load to local docker, it will takes a few minutes')
            command = 'tar xvzf %s' % (os.path.join(tempdir,os.path.basename(zipped_path)))
            if self.local:
                with lcd(tempdir):
                    result = self.command_run(command)
                    if result.failed:
                        raise LoadImageError("%s:local untar fail"%(self.ip))
                    else:
                        log.debug('untar success')
            else:
                with cd(tempdir):
                    result = self.command_run(command)
                    if result.failed:
                        raise LoadImageError("%s:remote untar fail"%(self.ip))

            zipped = (os.path.basename(zipped_path)).split('.')[0]
            temp_zipped = os.path.join(tempdir, zipped)
            command = 'ls %s' % (os.path.join(tempdir, zipped))
            result = self.command_run(command)
            if result.failed:
                raise LoadImageError("%s:list file fail"%(self.ip))
            else:
                log.info('start to load images, please wait..')
                for tfile in result.stdout.split():
                    command = 'docker load --input %s/%s'%(temp_zipped, tfile)
                    result = self.command_run(command)
                    if result.failed:
                        raise LoadImageError('%s:load %s fail'%(self.ip, tfile))
                   
        except LoadImageError, e:
            log.error(e)
            raise MyException('load image fail')
        finally:
            command = 'rm -rf %s'%(tempdir)
            result = self.command_run(command)

    def run_registry(self):
        log.info('start to run registry')
        if self.name:
            command = 'docker run -d --restart=always -p %s:5000 --name %s -v %s:/var/lib/registry %s'%(self.port, self.name, self.store, self.image)
        else:
            command = 'docker run -d --restart=always -p %s:5000 -v %s:/var/lib/registry %s'%(self.port, self.store, self.image)
        log.debug('command:%s'%command)

        result = self.command_run(command)
        if result.failed:
            raise MyException('command \'%s\' run fail'%(command))

    def push_private_registry(self, images_file):
        if not os.path.exists(images_file):
            raise MyException('image list file does not exist')

        command = 'docker images | awk \'{print $1":"$2}\''
        result = self.command_run(command)
        if result.failed:
            raise MyException('get images failed')
        else:
            if self.local:
                dockerimages = result.stdout.strip().split('\n')
            else:
                dockerimages = result.stdout.strip().split('\r\n')

        try:
            f = open(images_file, 'r')
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
                            log.debug('tag image found,skip')
                            tag_image_exist = True
                            break
                        
                    if not tag_image_exist:
                        command = 'docker tag %s %s'%(li, newimage)
                        result = self.command_run(command)
                        if result.failed:
                            raise MyException('docker tag fail')
                    command = 'docker push %s'%(newimage)
                    result = self.command_run(command)
                    if result.failed:
                        raise MyException(command+" fail")
                #need some cleanup?
            except Exception, e:
                raise MyException(str(e))
            finally:
                f.close()
        except Exception, e:
            raise MyException('open %s fail:%s'%(images_file,str(e)))

class RancherServer(Container):
 #   def __init__(self, registry_ip, registry_port, registry_password, ip, port, password):
    def __init__(self, registry_ip, registry_port, ip, port, password = None, registry_password = None):

        if (not registry_ip or not registry_port or 
            not ip or not port) :
            raise ContainerParameterError

        image = 'rancher/server:latest'
        Container.__init__(self, ip, image, port, password)
        self.registry_ip = registry_ip
        self.registry_port = registry_port
        self.password = password
        self.image = image
        self.registry_password = registry_password
  
        if self.ip == self.registry_ip:
            self.registry_password = self.password
        else:
            if not self.registry_password: 
                content='Enter the %s\'s password:'%(self.registry_ip)
                self.registry_password = getpass.getpass(prompt=content)

    def check_registry(self):
        #command = 'docker ps | awk \'{print $2}\' | grep %s:%s/registry:2'%(self.registry_ip, self.registry_port)
        command = 'docker ps | awk \'{print $2}\' | grep registry:2'
        if self.registry_ip == get_hostip():
            with settings(hide('warnings','stdout','running','stderr'),warn_only=True):
                result = local(command)
                if result.failed:
                    raise MyException('registry is not running')
                else:
                    log.info('check registry success') 
                    return
        else:
            log.info('now check registry is running ?')
            i = 6
            while i:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.registry_ip, 22, "root",self.registry_password)
                    return 
                except paramiko.ssh_exception.AuthenticationException, e: 
                    log.error(e)
                    i = i-1
                    if i == 0:
                        raise MyException("Over 5 times input wrong password...")
                    content = "please input registry \'%s\' correct password:"%(self.registry_ip)
                    self.registry_password = getpass.getpass(content)

                except Exception, e:
                    raise MyException(str(e)) 
                finally:
                    ssh.close()
            if i <= 0:
                raise MyException("Over 5 times input wrong password...")
            env.host_string = "%s:%s"%(self.registry_ip ,22) 
            env.password = self.registry_password
            with settings(hide('warnings','stdout','running','stderr'),warn_only=True):
                result = run(command)
                if result.failed:
                    raise MyException('registry is not running')
                else:
                    log.info('check registry success') 
                    return 

    def pull_image(self):
        command = 'docker images | awk \'{print $1":"$2}\'' 
        result = self.command_run(command)
        if result.failed:
            logging.warn('can\'t get docker images')
        else:
            need_pull = True
            rancher_server_image = 'docker.io/%s'%(self.image)
            registry_rancher_server_image = '%s:%s/%s'%(self.registry_ip, self.registry_port, self.image)
            if self.local:
                dockerimages =  result.stdout.strip().split('\n')
            else:
                dockerimages =  result.stdout.strip().split('\r\n')
            for image in dockerimages:
                if image == rancher_server_image:
                    log.info('image[%s] exists, skipping pull'%(rancher_server_image))
                    return
                if image == registry_rancher_server_image:
                    log.debug('image[%s] exists, skipping pull, need tag'%(registry_rancher_server_image))
                    need_pull = False

            if need_pull:
                command = 'docker pull %s:%s/%s'%(self.registry_ip, self.registry_port, self.image)
                result = self.command_run(command)
                if result.failed:
                    raise MyException('%s fail'%(command))

            #need to add check for images.existence
            command = 'docker tag %s:%s/%s docker.io/%s'%(self.registry_ip, self.registry_port, self.image, self.image)
            result = self.command_run(command)
            if result.failed:
                    raise MyException('%s fail'%(command))

    def run_server(self):
        command = 'docker run -d --restart=always -p %s:8080 %s:%s/%s' % (self.port, self.registry_ip, self.registry_port, self.image)
        result = self.command_run(command)
        if result.failed:
            raise MyException('run rancher server fail')
        else:
            log.info('rancher server start to run..')

    def restart_docker(self):
        #registry is running ,it have already set conf, and restart docker daemon, don't need to do this again
        if self.registry_ip == self.ip:
            return
        command = 'systemctl restart docker'
        result = self.command_run(command)
        if result.failed:
            log.info('restart docker fail....')
            sys.exit(1)

class RegistryFrontend(Container):
    def __init__(self, ip, registry_ip, registry_port, port, name=None, password=None, registry_password=None):
        if not registry_ip or not registry_port:
            raise ContainerParameterError

        image = 'konradkleine/docker-registry-frontend:v2'
        Container.__init__(self, ip, image, port,password)
        self.registry_ip = registry_ip
        self.registry_port = registry_port
        self.registry_password = registry_password
        self.name = name

        if not self.registry_password:
            content='Enter the %s\'s password:'%(self.registry_ip)
            self.registry_password = getpass.getpass(prompt=content)
            
    def run_container(self):
        if self.name:
            command = 'docker run -d  --restart=always -e ENV_DOCKER_REGISTRY_HOST=%s -e ENV_DOCKER_REGISTRY_PORT=%s -e ENV_MODE_BROWSE_ONLY=false -p %s:80 --name %s %s'%(self.registry_ip, self.registry_port, self.port, self.name, self.image)
        else:
            command = 'docker run -d  --restart=always -e ENV_DOCKER_REGISTRY_HOST=%s -e ENV_DOCKER_REGISTRY_PORT=%s -e ENV_MODE_BROWSE_ONLY=false -p %s:80 %s'%(self.registry_ip, self.registry_port, self.port, self.image)

        result = self.command_run(command)
        if result.failed:
            raise ContainerRunError(command)
        else:
            log.info('Web server container start')

    def pull_image(self):
        command = 'docker images | awk \'{print $1":"$2}\'' 
        result = self.command_run(command)
        if result.failed:
            raise DockerListImageError
        else:
            need_pull = True
            frontend_image = 'docker.io/%s'%(self.image)
            
            registry_frontend_image = '%s:%s/%s'%(self.ip, self.port,self.image)
            if self.local:
                dockerimages = result.stdout.strip().split('\n')
            else:
                dockerimages = result.stdout.strip().split('\r\n')
            for image in dockerimages:
                if image == frontend_image:
                    log.info('image[%s] exists, skipping pull'%(frontend_image))
                    return
                if image == registry_frontend_image:
                    log.debug('image[%s] exists, skipping pull, but need tag'%(registry_frontend_image))
                    need_pull = False

                    
            #增加镜像是否存在的判断
            if need_pull: 
                command = 'docker pull %s:%s/%s'%(self.registry_ip, self.registry_port, self.image)
                result = self.command_run(command)
                if result.failed:
                    raise MyException('pull images failed')
            #need to add check for images.existence
            tag_image = 'docker.io/%s'%(self.image)
            for j in dockerimages:
                log.debug('image to match:%s --->%s'% (j, tag_image))
                if j == tag_image:
                    log.info('%s exist, skip tag'%(tag_image))
                    return 

            command = 'docker tag %s:%s/%s docker.io/%s'%(self.registry_ip, self.registry_port, self.image, self.image)
            result = self.command_run(command)
            if result.failed:
                raise MyException('tag %s:%s/%s images failed'%(self.registry_ip, self.registry_port, self.image))

    def check_registry(self):
        #command = 'docker ps | awk \'{print $2}\' | grep %s:%s/registry:2'%(self.registry_ip, self.registry_port)
        command = 'docker ps | awk \'{print $2}\' | grep registry:2'
        if self.registry_ip == get_hostip():
            with settings(hide('warnings','stdout','running','stderr'),warn_only=True):
                result = local(command)
                if result.failed:
                    raise MyException('registry is not running')
                else:
                    log.info('check registry success')
                    return 
        else:
            log.info('now check registry is running ?')
            i = 6
            while i:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.registry_ip, 22, "root",self.registry_password)
                    break 
                except paramiko.ssh_exception.AuthenticationException, e: 
                    log.error(e)
                    i = i-1
                    if i == 0:
                        raise MyException("Over 5 times input wrong password...")
                    content = "please input registry \'%s\' correct password:"%(self.registry_ip)
                    self.registry_password = getpass.getpass(content)

                except Exception, e:
                    raise MyException(str(e)) 
                finally:
                    ssh.close()
            if i <= 0:
                raise MyException("Over 5 times input wrong password...")

            env.host_string = "%s:%s"%(self.registry_ip ,22) 
            env.password = self.registry_password
            with settings(hide('warnings','stdout','running','stderr'),warn_only=True):
                result = run(command)
                if result.failed:
                    raise MyException('registry is not running')
                else:
                    log.info('check registry success')
                    return 

    def restart_docker(self):
        #registry is running ,it have already set conf, and restart docker daemon, don't need to do this again
        if self.registry_ip == self.ip:
            return
        
        command = 'systemctl restart docker'
        result = self.command_run(command)
        if result.failed:
            log.info('restart docker fail....')
            sys.exit(1)

class RancherAgent(Container):
    def __init__(self, registry_ip, registry_port, server_ip, server_port, ip, add_host_command, registry_password=None, server_password=None, password=None):
        if not registry_ip or not registry_port or not server_ip or not server_port or not ip or not add_host_command:
            raise ContainerParameterError

        port = '1024'
        image = 'rancher/agent:v0.8.2'
        Container.__init__(self, ip, image, port,password)

        self.registry_ip = registry_ip
        self.registry_port = registry_port
        self.registry_password = registry_password
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_password = server_password
        self.command = add_host_command
        self.port = None
        
        if not self.registry_password:
            content='Enter the registy(%s)\'s password:'%(self.registry_ip)
            self.registry_password = getpass.getpass(prompt=content)
        if not self.server_password:
            content='Enter the rancher server(%s)\'s password:'%(self.server_ip)
            self.server_password = getpass.getpass(prompt=content)

        if not password:
            content='Enter the Agent(%s)\'s password:'%(self.ip)
            self.password = getpass.getpass(prompt=content)

    def check_registry(self):
     #   command = 'docker ps | awk \'{print $2}\' | grep %s:%s/registry:2'%(self.registry_ip, self.registry_port)
        command = 'docker ps | awk \'{print $2}\' | grep registry:2'
        if self.registry_ip == get_hostip():
            with settings(hide('stdout','stderr','running','warnings'),warn_only=True):
                result = local(command)
                if result.failed:
                    raise MyException('registry is not running')
                else:
                    log.info('check registry success')
                    return
        else:
            log.info('now check registry is running ?')
            i = 6
            while i:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.registry_ip, 22, "root",self.registry_password)
                    return 
                except paramiko.ssh_exception.AuthenticationException, e: 
                    log.error(e)
                    i = i-1
                    if i == 0:
                        raise MyException("Over 5 times input wrong password...")
                    content = "please input registry \'%s\' correct password:"%(self.registry_ip)
                    self.registry_password = getpass.getpass(content)

                except Exception, e:
                    raise MyException(str(e)) 
                finally:
                    ssh.close()
            if i <= 0:
                raise MyException("Over 5 times input wrong password...")

            env.host_string = "%s:%s"%(self.registry_ip ,22) 
            env.password = self.registry_password
            with settings(hide('stdout','stderr','running','warnings'),warn_only=True):
                result = run(command)
                if result.failed:
                    raise MyException('registry is not running')
                else:
                    log.info('check registry success')
                    return
            
    def check_rancher_server(self):
        command = 'docker ps | awk \'{print $2}\' | grep %s:%s/rancher/server:latest'%(self.registry_ip, self.registry_port)
        if self.server_ip == get_hostip():
            with settings(hide('running','warnings','stdout','stderr'),warn_only=True):
                result = local(command)
                if result.failed:
                    raise MyException('rancher server is not running')
                else:
                    log.info('check rancher server success')
        else:
            i = 6
            while i:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.server_ip, 22, "root",self.server_password)
                    return 
                except paramiko.ssh_exception.AuthenticationException, e: 
                    log.error(e)
                    i = i-1
                    if i == 0:
                        raise MyException("Over 5 times input wrong password...")
                    content = "please input server \'%s\' correct password:"%(self.server_ip)
                    self.server_password = getpass.getpass(content)

                except Exception, e:
                    raise MyException(str(e)) 
                finally:
                    ssh.close()
            if i <= 0:
                raise MyException("Over 5 times input wrong password...")

            env.host_string = "%s:%s"%(self.server_ip ,22) 
            env.password = self.server_password
            with settings(hide('running','warnings','stdout','stderr'),warn_only=True):
                result = run(command)
                if result.failed:
                    raise MyException('rancher server is not running')
                else:
                    log.info('check rancher server success')
        
    def check_command(self):
        match_string = r'.*http://%s:%s/v1/scripts/.*'%(self.server_ip,self.server_port)
        log.info('%s'%match_string)
        searchObj = re.search(match_string, self.command, re.I)
        if not searchObj:
            raise MyException('invalid command:%s'%self.command)

    def check_port_used(self):
        return False

            
    def pull_image(self):
        command = 'docker images | awk \'{print $1":"$2}\'' 
        result = self.command_run(command)
        if result.failed:
            raise MyException('can\'t get docker images')
        else:
            agent_image = 'docker.io/%s'%(self.image)
            agent_instance_image = 'docker.io/rancher/agent-instance:v0.6.0'
            if self.local: 
                dockerimages = result.stdout.strip().split('\n')
            else:
                dockerimages = result.stdout.strip().split('\r\n')

            e_agent = False
            e_instance = False
            t_agent_instance = False
            t_agent = False

            for image in dockerimages:
                if image == agent_image:
                    t_agent = True
                    continue
                if  image == agent_instance_image:
                    t_agent_instance = True
                    continue
                r_agent = agent_image.replace('docker.io','%s:%s'%(self.registry_ip, self.registry_port))
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
                    raise MyException('run \'%s\' fail'%command)
                    
            if not t_agent_instance:
                command = 'docker tag %s:%s/rancher/agent-instance:v0.6.0 docker.io/rancher/agent-instance:v0.6.0'%(self.registry_ip, self.registry_port)
                result = self.command_run(command)
                if result.failed:
                    raise MyException('run \'%s\' fail'%command)

            if not e_agent:
                command = 'docker pull %s:%s/rancher/agent:v0.8.2'%(self.registry_ip, self.registry_port)
                result = self.command_run(command)
                if result.failed:
                    raise MyException('run \'%s\' fail'%command)
            
            if not t_agent:
                command = 'docker tag %s:%s/rancher/agent:v0.8.2 docker.io/rancher/agent:v0.8.2'%(self.registry_ip, self.registry_port)
                result = self.command_run(command)
                if result.failed:
                    raise MyException('run \'%s\' fail'%command)

    def run_agent(self):
        result = self.command_run(self.command) 
        if result.failed:
            raise MyException('run \'%s\' fail'%self.command)

    def restart_docker(self):
        #registry is running ,it have already set conf, and restart docker daemon, don't need to do this again
        if self.registry_ip == self.ip or self.server_ip == self.ip:
            return
        
        command = 'systemctl restart docker'
        result = self.command_run(command)
        if result.failed:
            log.info('restart docker fail....')
            sys.exit(1)

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
        if not hostip:
            log.error('can\'t get local host ip')
            sys.exit(1)

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

    try:
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
    except ConfigParser.NoOptionError, e:
        log.error(str(e)+":Please make sure sections/options in your conf correct")
        sys.exit(1)

    try:
        # rancher agent
        if not conf_db['registry_ip'] or  not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$',conf_db['registry_ip']):
           raise MyException('Invalid conf argument [REGISTRY]/ip=\'%s\': not ip address or empty'%(conf_db['registry_ip'])) 


        if not conf_db['registry_port'] or not re.match(r'^\d*$', conf_db['registry_port']):
           raise MyException('Invalid conf argument [REGISTRY]/port= \'%s\': not digits or empty'%(conf_db['registry_port'])) 

        if not conf_db['registry_store'] or not conf_db['registry_store'].startswith('/'):
           raise MyException('Invalid conf argument [REGISTRY]/store=\'%s\':not absolute path or empty'%(conf_db['registry_store'])) 

        #rancher server
        if not conf_db['server_ip'] or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$',conf_db['server_ip']):
           raise MyException('Invalid conf argument [SERVER]/ip=\'%s\': not ip address or empty'%(conf_db['server_ip'])) 

        if not conf_db['server_port'] or not re.match(r'^\d*$', conf_db['server_port']):
           raise MyException('Invalid conf argument [SERVER]/port=\'%s\':no digits or empty'%(conf_db['server_port'])) 

        #registry frontend

        if not conf_db['registry_frontend_ip'] or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$',conf_db['registry_frontend_ip']):
           raise MyException('Invalid conf argument [REGISTRY_FRONETEND]/ip= \'%s\': not ip address or empty'%(conf_db['registry_frontend_ip'])) 

        if not conf_db['registry_frontend_port'] or not re.match(r'^\d*$', conf_db['registry_frontend_port']):
           raise MyException('Invalid conf argument [REGISTRY_FRONTEND]/port=\'%s\': not  digits or empty'%(conf_db['registry_frontend_port'])) 

    except MyException, e:
        log.error(e)
        sys.exit(1)

    return conf_db

def encrypt_password(password):
    if not password:
        raise MyException('invalid arg')
    msg_text = password.rjust(32)
    cipher = AES.new(_secret_key, AES.MODE_ECB)
    encoded = base64.b64encode(cipher.encrypt(msg_text))
    return encoded
 
def decrypt_password(password_en):
    if not password_en:
        raise MyException('invalid arg')
    ciper = AES.new(_secret_key, AES.MODE_ECB)
    decoded = cipher.decrypt(base64.b64decode(password_en))
    return decoded.strip()
    

def check_password(ip, password):
    if not ip:
        raise MyException('Invalid must not be empty')
    if not password:
        content = "please input \'%s\' password:"%(ip)
        password = getpass.getpass(content)

    i = 6 
    while i:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip, port=22, username="root", password=password)
            break
        except paramiko.ssh_exception.AuthenticationException, e: 
            log.error(e)
            i = i-1
            if i == 0:
                raise MyException("Over 5 times input wrong password...")
            content = "please input \'%s\' correct password:"%(ip)
            password = getpass.getpass(content)
            log.debug('password:%s'%(password))

        except paramiko.ssh_exception.BadHostKeyException, e:
            raise MyException(str(e))
        except Exception, e:
            raise MyException(str(e)) 
        finally:
            ssh.close()
    if i <= 0:
        raise FiveTimeWrongPWError("Over 5 times input wrong password...")
    else:
        return password

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
        sys.exit(1)

    conf_db = {}
    agents_conf = {}
    ips = {}
    pws = {}

    section = 'AGENT'
    for options in config.options(section):
        if options == 'rancher-server-command':
            if not config.get(section, options):
                raise MyException('Must set rancher-server-command option, get it from rancher server web page > ADD HOST PAGE')
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
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$',ipaddr):
                    raise MyException('Invalid conf argument \'%s\': must be ip address'%(ipaddr)) 

            else:
                log.info('skip EMPTY option:%s'%(options))
        if options.startswith('password'):
            password = clean_str(config.get(section, options))
            pws[options] = password
                
    for ipkey in ips.keys():
        if agents_conf.has_key(ips[ipkey]):
            log.info('skip duplicate host:%s'%(ips[ipkey]))
            continue
        agents_conf[ips[ipkey]]=''
        ipindex = ipkey.replace('ip', '')
        for pwkey in pws.keys():
            if ipindex == pwkey.replace('password', ''):
                agents_conf[ips[ipkey]] = pws[pwkey]
                break

        for agentkey in agents_conf.keys():
     #       if not agents_conf[agentkey]:
     #           content='Enter the %s\'s password:'%(agentkey)
     #           agents_conf[agentkey]= getpass.getpass(prompt=content)
            try:
                pw = check_password(agentkey, agents_conf[agentkey])
                agents_conf[agentkey] = pw
            except Exception, e:
                log.info(str(e))
                if confirm('Skip \'%s\' Agent host?'):
                    log.info('now skip \'%s\' Agent host')
                    del agents_conf[agentkey]

    if len(agents_conf) == 1 and 'rancher-server-command' in agents_conf:
        raise MyException('Agents:missing ip/password pair')

    return agents_conf

def list_registry():
    command = 'docker images | awk \'{print $1":"$2}\''

#获取所有镜像
def list_container(image):
    command = 'docker ps | awk \'{print $2}\''


def setup_agent(conf_db, agents_conf, ip):
    
    try:
        agent = RancherAgent(registry_ip=conf_db['registry_ip'], 
                             registry_port=conf_db['registry_port'], 
                             registry_password=conf_db['registry_password'],
                             server_ip=conf_db['server_ip'],
                             server_port=conf_db['server_port'],
                             server_password=conf_db['server_password'],
                             ip=ip,
                             password=agents_conf[ip],
                             add_host_command=agents_conf['rancher-server-command']
                         )
    except ContainerParameterError:
        raise MyException('invalid conf, check if missing some conf')
    try: 
        agent.check_command()
        log.debug('agent command:%s'%(agent.command))
        agent.check_host()
        if agent.check_running():
            log.info('\'ip\'agent is running, skip...')
            return  
        agent.check_port_used()
        log.debug('\'%s\'agent check port succeeded'%(agent.ip))
        agent.check_rancher_server()
        log.debug('\'%s\'agent check port succeeded'%(agent.ip))
        agent.check_registry()
        agent.add_registry(agent.registry_ip, agent.registry_port)
        agent.restart_docker()
        log.info('\'%s\'pulling images...'%(agent.ip))
        agent.pull_image()
        log.info('\'%s\'running agent...'%(agent.ip))
        agent.run_agent()
    except MyException, e:
        raise MyException(str(e))

        
def main():

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'd',['debug'])
        for opt, arg in opts:
            if opt in ('-d', '--debug'):
                log.setLevel(logging.DEBUG)
                DEBUG=True
                
    except get.GetoptError:
        log.debug('invalid option, use default')

    script_dir_path =os.path.abspath(os.path.dirname(sys.argv[0]))
    config_path = script_dir_path+'/conf'
    zipped_path = script_dir_path+'/images_zipped.tar.gz'
    images_file = script_dir_path+'/imagelists'
    log.info("loading config from "+config_path)

    conf_db = parse_conf(config_path)
    while True:
        try:
            choose = raw_input("Install Private Registry,[Y]es/[N]o:").strip()[0].lower()
        except (EOFError,KeyboardInterrupt,IndexError):
            choose = 'q'
        if choose not in 'qyn':
            continue

        if choose == 'q':
            log.info("Quiting...")
            logging.shutdown()
            sys.exit(1) 
        elif choose == 'n':
            log.info("Cancel Private Registry install.")
            break
        else:
            log.info("Private Registry installing...")
            try:
                log.info('check Registry \'%s\' password:' %(conf_db['registry_ip']) )
                pw = check_password(conf_db['registry_ip'], conf_db['registry_password'])
                conf_db['registry_password'] = pw
                log.info('registry password check success')
                log.info('--------------------')
                log.debug('registry_password:%s'%(conf_db['registry_password']))
            except Exception, e:
                log.error(e)
                logging.shutdown()
                sys.exit(1)
            try:
                rg = Registry( port=conf_db['registry_port'],
                               ip=conf_db['registry_ip'],
                               store=conf_db['registry_store'],
                               name=conf_db['registry_name'],
                               password=conf_db['registry_password'],
                        )
            except ContainerParameterError:
                log.error('invalid argument')
                logging.shutdown()
                sys.exit(1)
            try:
                log.info('++++++++++++++')
                rg.check_host()
                rg.check_env()
                rg.load_images(zipped_path, images_file)
                rg.set_system_firewalld_selinux()
                if not rg.check_running():
                    rg.check_port_used()
                    log.info('start to run registry ')
                    rg.run_registry()
                    rg.add_registry(rg.ip, rg.port)
                    log.info('restart docker...')
                    rg.restart_docker()
                    log.info('push images....')
                    rg.push_private_registry(images_file)
                else:
                    log.info('registry is running, push new images')
                    rg.add_registry(rg.ip, rg.port)
                    log.info('restart docker...')
                    rg.restart_docker()
                    log.info('push images....')
                    rg.push_private_registry(images_file)
                break                    
            except (MyException, PortUsedError), e:
                log.error(e)
                logging.shutdown()
                sys.exit(1)

    while True:
        try:
            choose = raw_input("Install Rancher Server,[Y]es/[N]o:").strip()[0].lower()
        except (EOFError,KeyboardInterrupt,IndexError):
            choose = 'q'
        if choose not in 'qyn':
            continue

        if choose == 'q':
            log.info("Quiting...")
            logging.shutdown()
            sys.exit(1) 
        elif choose == 'n':
            log.info("Cancel Rancher Server install.")
            break
        else:
            log.info("Rancher Server installing...")
            try: 
                log.info('check Rancher Server \'%s\' password:' %(conf_db['server_ip']) )
                pw = check_password(conf_db['server_ip'], conf_db['server_password'])
                conf_db['server_password'] = pw
                log.info('rancher server password  check success')
            except Exception, e:
                log.error(e)
                logging.shutdown()
                sys.exit(1)

            try:
                rs = RancherServer(
                    registry_ip=conf_db['registry_ip'],
                    registry_port=conf_db['registry_port'], 
                    registry_password=conf_db['registry_password'], 
                    ip=conf_db['server_ip'], 
                    port=conf_db['server_port'],
                    password=conf_db['server_password'])
            except ContainerParameterError:
                log.error('invalid conf, check if missing some conf')
                logging.shutdown()
                sys.exit(1)

            try:  
                log.info('checking environment..')
                rs.check_host()
                rs.check_env()
                rs.check_registry()
                if rs.check_running():
                    log.info('rancher server is running')
                    break
                rs.check_port_used()
                rs.add_registry(rs.registry_ip,rs.registry_port)
                log.info('restart docker daemon...')
                rs.restart_docker()
                log.info('pulling images ...')
                rs.pull_image()
                log.info('running server...')
                rs.run_server()
                time.sleep(3)
                break
            except (MyException, PortUsedError), e:
                log.error(e)
                logging.shutdown()
                sys.exit(1)

    while True:
        try:
            choose = raw_input("Instal Registry Frontend,[Y]es/[N]o:").strip()[0].lower()
        except (EOFError,KeyboardInterrupt,IndexError):
            choose = 'q'
        if choose not in 'qyn':
            continue

        if choose == 'q':
            log.info("Quiting...")
            logging.shutdown()
            sys.exit(1) 
        elif choose == 'n':
            log.info("Cancel Registry Frontend install.")
            break
        else:
            log.info("Registry Frontend installing...")
            try:
                log.info('check Registry Frontend  \'%s\' password:' %(conf_db['registry_frontend_ip']) )
                pw = check_password(conf_db['registry_frontend_ip'], conf_db['registry_frontend_password'])
                conf_db['registry_frontend_password'] = pw
                log.info('registry frontend  password  check success')
            except Exception, e:
                log.error(e)
                logging.shutdown()
                sys.exit(1)

            try:
                rf = RegistryFrontend(
                  ip=conf_db['registry_frontend_ip'],
                  password=conf_db['registry_frontend_password'],
                  registry_ip=conf_db['registry_ip'],
                  registry_port=conf_db['registry_port'],
                  registry_password=conf_db['registry_password'],
                  port=conf_db['registry_frontend_port'],
                  name=conf_db['registry_frontend_name'])
            except ContainerParameterError:
                log.error('invalid conf, please check conf')
                logging.shutdown()
                sys.exit(1)

            try:
                rf.check_host()
                rf.check_env()
                if rf.check_running():
                    log.info('registry frontend is running')
                    break
                rf.check_port_used()
                rf.check_registry()
                rf.add_registry(rf.registry_ip, rf.registry_port)
                log.info('restart docker...')
                if conf_db['server_ip'] == rf.ip:
                    log.debug('server and registry in some server, skip restart docker to avoid breaking server\'s running')
                else:
                    rf.restart_docker()
                log.info('pulling image..')
                rf.pull_image()
                log.info('running registry frontend')
                rf.run_container()
            except (ContainerRunError, MyException, PortUsedError), e:
                log.error(e)
                logging.shutdown()
                sys.exit(1)

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
            logging.shutdown()
            sys.exit(1) 
        elif choose == 'n':
            log.info("Cancel Rancher Agents install.")
            break
        else:
            log.info("Rancher Agent installing...")
    
            try:
                agents_conf = parse_agent_conf(config_path)
            except MyException, e:
                log.error(e)
                logging.shutdown()
                sys.exit(1)

            try:
                for ip in agents_conf.keys():
                    if ip == 'rancher-server-command':
                        continue
                    log.info('----------------------------')
                    log.info('setup agent in \'%s\'...', ip)
                    setup_agent(conf_db, agents_conf, ip)
            except MyException, e:
                log.error('%s setup agent fail:%s, skip...',ip,e)
            except (KeyboardInterrupt, SystemExit), e:
                log.error(e)
                logging.shutdown()
                sys.exit(1)
            log.info('Adding agent finish')
            logging.shutdown()
            break
    fabric.network.disconnect_all()

            
if __name__ == '__main__':
    main()
