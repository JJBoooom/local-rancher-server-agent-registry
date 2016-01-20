#!/bin/bash

#将镜像保存成压缩包
set -e
#set -x


docker=$(which docker) > /dev/null 2>&1
images_zipped=$(dirname $0)/images_zipped
conf=$(dirname $0)/conf
imagelists=$(dirname $0)/imagelists
test_sh=$(dirname $0)/test.sh

#package_files="$conf $(dirname $0)/install.sh $images_zipped $imagelists $test_sh"
package_dir=$(dirname $0)/packages
package_tar=$(basename $package_dir).tar

save()
{
    set +e
    $docker save --output=$1 $2 
    if [ $? -ne 0 ];then
        rm $1
        exit 255
    fi
    set -e

#    local tar_gz="$1.gz"
#    gzip ./$1
#    mv $tar_gz $images_zipped/
    mv $1 $images_zipped/

}

#拉取docker hub镜像,并打包成tar包
save_imagelists()
{
    if [ ! -e $imagelists ];then
        echo "$0:missing image list"
        exit 255
    fi
    
    while read line           
    do           
        if [[  $line =~ ^\#+ ]] || 
            [[  "$line" =~ ^[[:space:]]*$ ]];then
            continue
        fi

        local image_tar=$(echo $line | cut -d/ -f 2-3 | cut -d: -f 1 | tr '/' '_' )

        echo $image_tar
        save $image_tar $line
    done < $imagelists
    
#    gzip $images_zipped
    images_zipped_tar = "$images_zipped.tar"
    tar cvf - `find $images_zipped -print`  > $images_zipped_tar
    gzip $images_zipped_tar
    

}


save_imagelists

if [ -d $package_dir ];then
    rm -rf $package_dir
fi

mkdir -p $package_dir
for i in $package_files
do
    cp -rf $i $package_dir/
done
tar cvf - `find $package_dir -print`  > $package_tar
gzip $package_tar

