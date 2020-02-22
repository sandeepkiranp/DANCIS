#!/bin/bash
ip="$(ifconfig | grep -A 1 'eno1' | tail -1 | awk '{print $2}'| awk --field-separator=":" '{print $2}')"
echo $ip
input=$1
i=0
echo "removing containers" 
docker ps -a -q

docker stop $(docker ps -a -q)

docker rm $(docker ps -a -q)

while IFS= read -r line
do
    if [ $i == 0 ]
    then
      i=1
      continue
    fi

  #echo "$line"

  name=`echo $line | awk '{print $1}'`
  lip=`echo $line | awk '{print $2}'`
  port=`echo $line | awk '{print $3}'`
  constr=`echo $line | awk '{print $4}'`

  if [ $ip == $lip ]
  then
    portstring="${port}:${port}" 

    echo $portstring

    if [ $constr == "C" ]
    then
      dstr="--memory=10m --memory-swap=10m --cpus=0.5"
    else
      dstr=""
    fi
    ./docker.sh $name $portstring $dstr &
  fi
done < "$input"
