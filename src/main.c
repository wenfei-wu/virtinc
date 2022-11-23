#include<stdio.h>

#include "switch.h"
#include "host.h"

int main(int argc, char** argv){
	printf("this file reads the parameters and the role of the node\n");
	int rank;
	if(rank==0){
		printf("Run host1\n");
	} else if(rank==1){
		printf("Run switch\n")
	} else if(rank==2){
		printf("Run host2\n")
	}

	return 0;
}
