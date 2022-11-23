#!/bin/bash

source topo.config

function CreateNodes(){
	echo "======================================"
	echo "Create Docker Container here, do it by yourself"
	for h in ${hosts[@]}; do
		echo create ${h}
	done
}

function CreateLinks(){
	echo "======================================"
	echo "Create Links, do it by yourself"
	total=${#links[*]}
	for ((i=0; i<$(($total)); i=i+4)) do
		echo ${links[$i]}, ${links[$i+1]}, ${links[$i+2]}, ${links[$i+3]}
	done
}


CreateNodes
CreateLinks
