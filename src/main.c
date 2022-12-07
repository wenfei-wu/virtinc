#include<stdio.h>
#include<string.h>

#include "net.h"

/*******************************************************************************
 *  TODO: refine the arguments later, together with the centralized mgmt methods
 ******************************************************************************/


int main(int argc, char** argv){
	printf("this file reads the parameters and the role of the node\n");
	
	if(strcmp(argv[1], "switch") == 0){
		init_switch(argc, argv);
		run_switch();
	}else if(strcmp(argv[1], "host1") == 0){
		run_host(SENDER, "key_value.txt");
	}else if(strcmp(argv[1], "host2") == 0){
		run_host(RECEIVER, NULL);
	}

	return 0;
}
