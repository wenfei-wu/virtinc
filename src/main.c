#include<stdio.h>
#include<string.h>

#include "net.h"

/*******************************************************************************
 *  TODO: refine the arguments later, together with the centralized mgmt methods
 ******************************************************************************/


int main(int argc, char** argv){
	printf("this file reads the parameters and the role of the node\n");
	
	if(strcmp(argv[1], "1") == 0){
		rank = SWITCH;
		init_switch();
		run_switch();
	}else if(strcmp(argv[1], "0") == 0){
		rank = SENDER;
		run_host1(argc, argv);
	}else if(strcmp(argv[1], "2") == 0){
		rank = RECEIVER;
		run_host2(argc, argv);
	}else if(strcmp(argv[1], "unblock_switch") == 0){
		rank = UNBLOCK_SWITCH;
		init_switch(argc, argv);
		run_unblock_switch();
	}

	return 0;
}
