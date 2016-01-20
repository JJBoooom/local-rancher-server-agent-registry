
 Local/Remote private registry + rancher server + registry frontend + rancher agent deployment.
 Images an inner network occasion which can't pull images from docker hub or other public registry, but want to deploy docker/rancher in his machines. 
 There is why the project build.
 
 + package.sh - need to run in a machine that can connect to Internet. It will pull all the images we need and save in a zipped file named 'images_zipped.tar.gz'

 + install.py - a python scripts used to deploy all thing we needs.

 + imagelists -  all images we need. package.sh and install.py will parse this file to pull/push images.

 + conf - configuration file used by install.py. It describes the how we deploy
 
 + clean.py - it will collect all hosts in the `conf ' file, and stop running containers, remove all existent ontainers, remove all images in these hosts 
