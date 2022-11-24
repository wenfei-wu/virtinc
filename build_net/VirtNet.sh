#!/bin/bash

source topo.config

function CreateImages()
{
	docker build -t mycontainer:v1.1 .
}

function CreateNodes(){
	echo "======================================"
	echo "Create Docker Container and Start it"
	for h in ${nodes[@]}; do
		docker create --cap-add NET_ADMIN --name $h mycontainer:v1.1
		docker start $h
		echo create $h
	done
}

function RunContainers() 
{
	for h in ${nodes[@]}; do
		docker start $h
	done
}

function StopContainers()
{
	for h in ${nodes[@]}; do
		docker stop $h
	done
}

function DestroyContainers()
{
	for h in ${nodes[@]}; do
		docker stop $h
		docker rm $h
	done
}

function DestroyImages()
{
	docker rmi mycontainer:v1.0
}

function CreateLinks(){
	echo "======================================"
	echo "Create Links"

	id=()
	for((i=0;i<3;i++));
	do
		id[$i]=$(sudo docker inspect -f '{{.State.Pid}}' ${nodes[$i]})
		ln -s /proc/${id[$i]}/ns/net /var/run/netns/${id[$i]}
	done

	id[3]=${id[1]}

 	total=${#links[*]}
	ipAddr=("10.0.0.1/24" "10.0.0.2/24" "10.0.1.1/24" "10.0.1.2/24")
	idx=0

	for ((i=0; i<$total; i=i+4)) do
		#echo ${links[$i]}, ${links[$i+1]}, ${links[$i+2]}, ${links[$i+3]}
		ip link add ${links[$i]}-${links[$i+1]} type veth peer name ${links[$i+2]}-${links[$i+3]}

		ip link set ${links[$i]}-${links[$i+1]} netns ${id[$idx]}
		ip netns exec ${id[$idx]} ip link set ${links[$i]}-${links[$i+1]} up
		ip netns exec ${id[$idx]} ip addr add ${ipAddr[$idx]} dev ${links[$i]}-${links[$i+1]}
		idx=$idx+1

		ip link set ${links[$i+2]}-${links[$i+3]} netns ${id[$idx]}
		ip netns exec ${id[$idx]} ip link set ${links[$i+2]}-${links[$i+3]} up
		ip netns exec ${id[$idx]} ip addr add ${ipAddr[$idx]} dev ${links[$i+2]}-${links[$i+3]}
		idx=$idx+1
	done
}


function DestroyLinks(){
	for((i=0;i<3;i++));
	do
		id[$i]=$(sudo docker inspect -f '{{.State.Pid}}' ${nodes[$i]})
		ip netns del ${id[$i]}
	done
}

#CreateImages
CreateNodes
CreateLinks
