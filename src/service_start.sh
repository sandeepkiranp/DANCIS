#!/bin/bash
ip="$(ifconfig | grep -A 1 'eno1' | tail -1 | awk '{print $2}')"
echo $ip
input=$1
i=0
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

  if [ $ip == $lip ]
  then
    echo "starting $name"
    ./service $name < ../software/pbc-0.5.14/param/a.param &
  fi
done < "$input"
