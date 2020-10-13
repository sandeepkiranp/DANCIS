name=$1
portstring=$2
dstr=$3

docker run --name $name $dstr -p $portstring -itd repository/dac_service

docker exec $name  mkdir -p /root/dac/services/$name

docker cp ../root/services.txt $name:/root/dac/root

docker cp ../services/$name/policy.txt $name:/root/dac/services/$name/

echo "starting $name"
docker exec -d $name /root/dac/src/service $name

