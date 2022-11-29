#include<stdio.h>
#include<string.h>

#include "net.h"

/*******************************************************************************
 *  TODO: refine the arguments later, together with the centralized mgmt methods
 ******************************************************************************/


int main(int argc, char** argv){
	printf("this file reads the parameters and the role of the node\n");
	int rank=0;
	char role[]="switch";
	if(strcmp(role, "switch")==0){
		init_switch(argc, argv);
		run_switch();
	}

	return 0;
}
