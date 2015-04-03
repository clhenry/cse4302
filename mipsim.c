#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUMREGS		32
#define MAXCHARS	128
#define MAXLABELS	16
#define MAXINSTRS	64
#define INSTR_BASE	0x4000
#define	DATA_BASE	0x1000
#define DATA_END	0x2000
#define BYTE_WIDTH	4
#define STAGES		5
#define MEMWB		3
#define EXMEM		2
#define IDEX		1
#define IFID		0

typedef enum OPCODE {
		ADD = 0,
		ADDI,
		SUB,
		BEQ,
		BNE,
		LW,
		SW,
		NOP
	} OPCODE;

typedef enum FLAGS {
	NONE = 0,
	STALL,
	BRANCH,
	EXMEMtoIDsrc1,
	EXMEMtoIDsrc2,
	EXMEMtoEXsrc1,
	EXMEMtoEXsrc2,
	MEMWBtoIDsrc1,
	MEMWBtoIDsrc2,
	MEMWBtoEXsrc1,
	MEMWBtoEXsrc2,
	WRBACK
} EVENT;

struct comboevent {
	EVENT forwardingEvent;
	EVENT branchStallEvent;
	EVENT writeBack;
};

OPCODE opStringToInt(char *opString) {
    switch(*opString) {
	case 'A' :
		if(strlen(opString) == strlen("ADD")) return ADD;
		return ADDI;
	case 'B' :
		if(opString[1] == 'E') return BEQ;
		return BNE;
	case 'L' :
		return LW;
	case 'S' :
		if(opString[1] == 'U') return SUB;
		return SW;
	default :
		return NOP;
	}
};

struct label_table {
    char *labelName;
    int instrAddr;
};

struct instruction {
    char opString[5];
    OPCODE op;
    int dest, destValue;
    int src1, src1Value;
    int src2, src2Value;
    int memAddr, offset;
    int immediate;
};



void stringToUpperCase(char *string) {
    int i;
    for(i = 0; string[i] != '\0'; i++)
    {
        if(string[i] > 96 && string[i] < 123) string[i] = string[i] - 32;
    }
}

//These are the registers placed inbetween stages
struct clockedstageregister {
    struct instruction *input, *output;
};

struct clockedpc {
    int input, output;
};

int parseTextFile(char *file, struct instruction *instrMemPtr, int *instructionCount, struct label_table *lTable);
//void validateLine(char *line);
//void textLineToInstructionMemory(void);
struct instruction * IFStage(struct instruction *instruction, int instructionCount, struct instruction *dummyOp);
struct instruction * IDStage(int *registerFile, struct clockedpc *PC, struct instruction *instruction, struct clockedstageregister *clockedStageRegister, struct instruction *BUBBLE, struct comboevent *flag);
struct instruction * EXStage(struct instruction *instruction, struct clockedstageregister *clockedStageRegister, struct comboevent *flag);
struct instruction * MEMStage(struct instruction *instruction, int *dataMemory, struct comboevent *flag);
void WBStage(int *registerFile, struct instruction *instruction, struct comboevent *flag);
void advanceClock(struct clockedpc *PC, struct clockedstageregister *stageRegister, struct comboevent *flag);

void instructionToString(struct instruction *instruction, char *stringBuf);
char * forwardingFlagToString(struct comboevent *flag);

int main(int argc, char *argv[])
{
    int argIndex;
	int runCycles;
	int CC;
	int registerFile[NUMREGS];
	struct label_table labelTable[MAXLABELS];
	struct instruction instructionMem[MAXINSTRS];
	int instructionCount;
	int dataMem[DATA_END - DATA_BASE];

	//Zero register file and data memory
	memset(registerFile, 0, NUMREGS);
	memset(dataMem, 0, DATA_END - DATA_BASE);

	//Extract filename from arguments passed to
	/*if(argc > 1) {
		for(argIndex = 1; argIndex < argc; argIndex++) {
			if(strcmp(argv[argIndex], "-f") == 0) break;
		}
	}
	else {
		printf("You need to at least specify a filename with the -f option and optionally the number of cycles with the -c option\n");
		return -1;
	}*/

	//if(parseTextFile(argv[argIndex + 1], instructionMem, &instructionCount, labelTable) < 0) return -1;

	if(parseTextFile("/home/thor/assembly.s", instructionMem, &instructionCount, labelTable) < 0) return -1;
	//Dummy operation
	struct instruction stall;
	stall.op = NOP;

	//Reset PC
	struct clockedpc PC;
	PC.input = 1;
	PC.output = 0;

	struct comboevent eventFlag;

	eventFlag.branchStallEvent = NONE;
	eventFlag.forwardingEvent = NONE;

	//Set initial clock cycle to 0
	CC = 0;

	//Pipeline registers
	struct clockedstageregister stageRegister[STAGES - 1];

	//File pipeline registers with dummy operations
	int i;
	for(i = 0; i < STAGES; i++)
    {
		stageRegister[i].input = &stall;
		stageRegister[i].output = &stall;
	}

	runCycles = 1;
	char humanReadableInstruction[24];
	instructionMem[instructionCount + 1].op = NOP;

	char userInput[5];

	while(stageRegister[MEMWB].output != &instructionMem[instructionCount + 1]) {

		if(runCycles > 0)
        {
		    if(runCycles == 1)
            {
				printf("\nNumber of cycles to execute: ");
				gets(userInput);
				if(*userInput == '\0')
                {
					continue;
				}
				else if(strtol(userInput, NULL, 0) == 0 || strtol(userInput, NULL, 0) < 1) {
					printf("\nThat entry is invalid");
					continue;
				}
				else runCycles = strtol(userInput, NULL, 0);
			}
			else if(runCycles > 1) 	runCycles--;
		}
		//IF stage takes struct instruction * and returns the same
		stageRegister[IFID].input = IFStage(&instructionMem[PC.output], instructionCount, &stall);
		stageRegister[IDEX].input = IDStage(registerFile, &PC, stageRegister[IFID].output, stageRegister, &stall, &eventFlag);
		stageRegister[EXMEM].input = EXStage(stageRegister[IDEX].output, stageRegister, &eventFlag);
		stageRegister[MEMWB].input = MEMStage(stageRegister[EXMEM].output, dataMem, &eventFlag);
		WBStage(registerFile, stageRegister[MEMWB].output, &eventFlag);

		printf("\n\nCC: %d | NEXT PC = 0x%x\n", CC++, ((PC.input * BYTE_WIDTH) + INSTR_BASE));
		printf("FORWARDING PATH IN USE: %s | ", forwardingFlagToString(&eventFlag));
		printf("WRITING TO REGISTER: ");
		if(eventFlag.writeBack == NONE)
        {
			printf("NONE\n");
		}
		else printf("$%d | VALUE: 0x%x\n", stageRegister[MEMWB].output->dest, stageRegister[MEMWB].output->destValue);

		instructionToString(&instructionMem[PC.output], humanReadableInstruction);
		printf("IF: %s", humanReadableInstruction);
		for(i = IFID; i <= MEMWB; i++)
        {
			instructionToString(stageRegister[i].output, humanReadableInstruction);
			switch(i) {
			case IFID :
				printf(" | ID: ");
				break;
			case IDEX :
				printf(" | EX: ");
				break;
			case EXMEM:
				printf(" | MEM: ");
				break;
			case MEMWB :
				printf(" | WB: ");
				break;
			}
			printf("%s", humanReadableInstruction);
		}
		advanceClock(&PC, stageRegister, &eventFlag);
	}

	return EXIT_SUCCESS;
}


 struct instruction * IFStage(struct instruction *instruction, int instructionCount, struct instruction *dummyOp) {
	 if(instruction < &instruction[instructionCount]) return instruction;
	 else return dummyOp;
 }

 struct instruction * IDStage(int *registerFile, struct clockedpc *PC, struct instruction *instruction, struct clockedstageregister *clockedStageRegister, struct instruction *BUBBLE, struct comboevent *flag) {
	 if(instruction->op != NOP) {
		 if(instruction->op == BEQ || instruction->op == BNE) {
			 //Fetch src1 operands from register file
			 if(instruction->src1 == 0) {
				 instruction->src1Value = 0;
			 }
			 else instruction->src1Value = registerFile[instruction->src1];

			 //Fetch src2 operands from register file
			 if(instruction->src2 == 0) {
				 instruction->src2Value = 0;
			 }
			 else instruction->src2Value = registerFile[instruction->src2];

			 //If instruction is a branch we need the right operands now so we are either going to stall
			 //or be able to compute the branch
			 if(instruction->op == BEQ || instruction->op == BNE) {
				 //Check if there is an instruction in the pipeline that may contain the result we are waiting for
				 //Check the EX stage for ALU OP, we would just need 1 stall before we could forward back to ID
				 if((clockedStageRegister[IDEX].output->dest == instruction->src1 || clockedStageRegister[IDEX].output->dest == instruction->src2) && (clockedStageRegister[IDEX].output->dest != 0) && (clockedStageRegister[IDEX].output->op <= SUB || clockedStageRegister[IDEX].output->op == LW)) {
					 flag->branchStallEvent = STALL;
					 return BUBBLE;
				 }
				 //Check the MEM stage for LW OP, we would just need 1 stall before we could forward back to ID
				 else if ((clockedStageRegister[EXMEM].output->dest == instruction->src1 || clockedStageRegister[EXMEM].output->dest == instruction->src2) && (clockedStageRegister[EXMEM].output->dest != 0) && (clockedStageRegister[EXMEM].output->op == LW)) {
					 flag->branchStallEvent = STALL;
					 return BUBBLE;
				 }
				 //Forward from recently computed ALU instruction if required
				 else if(clockedStageRegister[EXMEM].output->op <= SUB && (clockedStageRegister[EXMEM].output->dest != 0) && (clockedStageRegister[EXMEM].output->dest == instruction->src1 || clockedStageRegister[EXMEM].output->dest == instruction->src2)) {
					 if(clockedStageRegister[EXMEM].output->dest == instruction->src1) {
						 //Raise forwarding flag for EXMEM.output -> IDEX.src1
						 flag->forwardingEvent = EXMEMtoIDsrc1;
						 instruction->src1Value = clockedStageRegister[EXMEM].output->destValue;
					 }
					 else {
						 //Raise forwarding flag for EXMEM.output -> IDEX.src2
						 flag->forwardingEvent = EXMEMtoIDsrc2;
						 instruction->src2Value = clockedStageRegister[EXMEM].output->destValue;
					 }
				 }
				 //The stall conditions have been taken care of above. The forwarding conditions are taken care of below
				 else if((clockedStageRegister[MEMWB].output->op <= SUB ||clockedStageRegister[MEMWB].output->op == LW) && (clockedStageRegister[MEMWB].output->dest != 0) && (clockedStageRegister[MEMWB].output->dest == instruction->src1 || clockedStageRegister[MEMWB].output->dest == instruction->src2)) {
					 if(clockedStageRegister[EXMEM].output->dest == instruction->src1) {
						 //Raise forwarding flag for MEMWB.output -> IDEX.src1
						 flag->forwardingEvent = MEMWBtoIDsrc1;
					 	 instruction->src1Value = clockedStageRegister[MEMWB].output->destValue;
					  }
					  else {
					 	 //Raise forwarding flag for MEMWB.output -> IDEX.src2
						 flag->forwardingEvent = MEMWBtoIDsrc2;
					 	 instruction->src2Value = clockedStageRegister[MEMWB].output->destValue;
					  }
				 }
				 //And finally if we didn't stall we can compute the new PC depending on the branch instruction
				 if(instruction->op == BEQ && (instruction->src1Value == instruction->src2Value)) {
					 PC->input = PC->input + instruction->offset;
					 clockedStageRegister[IFID].input = BUBBLE;
					 //Clear the stall flag if we were waiting on a result previously but got it forwarded
					// if(*flag == STALL) *flag = NONE;
				 }
				 else if(instruction->op == BNE && (instruction->src1Value != instruction->src2Value)) {
					 PC->input = PC->input + instruction->offset;
					 clockedStageRegister[IFID].input = BUBBLE;
					 //if(*flag == STALL) *flag = NONE;
				 }
			 }
		 }
		 else if(instruction->op != BEQ && instruction->op != BNE) {
		 	//If there is a LW in the EX stage and the result of that operation is needed we must stall in the ID stage
		 	if(clockedStageRegister[IDEX].output->op == LW && (clockedStageRegister[IDEX].output->dest != 0) && (clockedStageRegister[IDEX].output->dest == instruction->src1 || clockedStageRegister[IDEX].output->dest == instruction->src2)) {
		 		flag->branchStallEvent = STALL;
		 		return BUBBLE;
			 }
		 	else if(flag->branchStallEvent == STALL) flag->branchStallEvent = NONE;
		 	/*else if(clockedStageRegister[IDEX].input->op == BNE || clockedStageRegister[IDEX].input->op == BEQ) {
		 		//If we previously took a branch then the instruction in the ID stage should be
		 		//thrown away instead of forwarded
		 		if(clockedStageRegister[IDEX].input->op == BEQ && clockedStageRegister[IDEX].input->src1Value == clockedStageRegister[IDEX].input->src2Value) {
		 			return BUBBLE;
		 		}
		 		else if(clockedStageRegister[IDEX].input->op == BNE && clockedStageRegister[IDEX].input->src1Value != clockedStageRegister[IDEX].input->src2Value) {
		 			return BUBBLE;
		 		}
		 	}*/
		 }
		 //Clear "branch taken" flag and "thow away" current instruction

	 }
	 return instruction;
 }

 struct instruction * EXStage(struct instruction *instruction, struct clockedstageregister *clockedStageRegister, struct comboevent *flag) {
	 //Determine if we can forward from the previous instruction that was in the EX stage
	 if(clockedStageRegister[EXMEM].output->op <= SUB && (clockedStageRegister[EXMEM].output->dest != 0) && (clockedStageRegister[EXMEM].output->dest == instruction->src1 || clockedStageRegister[EXMEM].output->dest == instruction->src2) && (instruction->op != BEQ && instruction->op != BNE)) {
		if(clockedStageRegister[EXMEM].output->dest == instruction->src1) {
			//Raise forwarding flag for EXMEM.output -> EX.src1
			flag->forwardingEvent = EXMEMtoEXsrc1;
			instruction->src1Value = clockedStageRegister[EXMEM].output->destValue;
		}
		else {
			 //Raise forwarding flag for EXMEM.output -> EX.src2
			 flag->forwardingEvent = EXMEMtoEXsrc2;
			 instruction->src2Value = clockedStageRegister[EXMEM].output->destValue;
		}
	}
	//Determine if we can forward from the previous instruction that was in the MEM stage
	else if((clockedStageRegister[MEMWB].output->op <= SUB || clockedStageRegister[MEMWB].output->op == LW) && (clockedStageRegister[MEMWB].output->dest != 0) && (clockedStageRegister[MEMWB].output->dest == instruction->src1 || clockedStageRegister[MEMWB].output->dest == instruction->src2) && (instruction->op != BEQ && instruction->op != BNE)) {
		if(clockedStageRegister[EXMEM].output->dest == instruction->src1) {
			 //Raise forwarding flag for MEMWB.output -> EX.src1
			 flag->forwardingEvent = MEMWBtoEXsrc1;
			 instruction->src1Value = clockedStageRegister[MEMWB].output->destValue;
		}
		else {
			//Raise forwarding flag for MEMWB.output -> EX.src2
			flag->forwardingEvent = MEMWBtoEXsrc2;
		 	instruction->src2Value = clockedStageRegister[MEMWB].output->destValue;
		}
	 }
	 //With the possible forwarding completed we can perform ALU operation on valid instructions
	 if(instruction->op <= SUB || instruction->op == LW || instruction->op == SW) {
	 	if(instruction->op == LW) {
	 		instruction->memAddr = instruction->src1Value + instruction->offset;
	 	}
	 	else if(instruction->op == SW) {
	 		instruction->memAddr = instruction->src2Value + instruction->offset;
	 	}
	 	else if(instruction->op == ADDI) {
	 		instruction->destValue = instruction->src1Value + instruction->immediate;
	 	}
	 	else if(instruction->op == SUB) {
	 		instruction->destValue = instruction->src1Value - instruction->src2Value;
	 	}
		else instruction->destValue = instruction->src1Value + instruction->src2Value;
	}
	return instruction;
 }

 struct instruction * MEMStage(struct instruction *instruction, int *dataMemory, struct comboevent *flag) {
	 if(instruction->op == LW || instruction->op == SW) {
		 //Make sure addresses for memory are < 0x1000 and > 0x2000
		 if(instruction->op == LW) instruction->destValue = dataMemory[(instruction->memAddr - DATA_BASE)/BYTE_WIDTH];
		 else dataMemory[(instruction->memAddr - DATA_BASE) / BYTE_WIDTH] = instruction->src1Value;
	 }
	 return instruction;
 }

 void WBStage(int *registerFile, struct instruction *instruction, struct comboevent *flag) {
	 if(instruction->op <= SUB || instruction->op == LW) {
	 	//Case where $0 is a destination register
	 	if(instruction->dest == 0) registerFile[instruction->dest] = 0;
	 	else {
	 		registerFile[instruction->dest] = instruction->destValue;
	 		flag->writeBack = WRBACK;
	 	}
	 }
 }

 void advanceClock(struct clockedpc *PC, struct clockedstageregister *stageRegister, struct comboevent *flag) {
	 //If the instruction coming into the ID stage does not match the one going into the EX stage
	 //then there must have been a stall so we should not increment the PC
	 if(flag->branchStallEvent != STALL) {
		 stageRegister[IFID].output = stageRegister[IFID].input;
	 	 PC->output = PC->input;
	 	 PC->input =PC->input + 1;
	 }
	 //Clear all flags
	if(flag->branchStallEvent > BRANCH || flag->forwardingEvent > BRANCH || flag->writeBack > NONE) {
		 if(flag->branchStallEvent > BRANCH) {
			 flag->branchStallEvent = NONE;
		 }
		 if(flag->forwardingEvent > BRANCH) {
			 flag->forwardingEvent = NONE;
		 }
		 if(flag->writeBack > NONE) {
			 flag->writeBack = NONE;
		 }
	 }

	 stageRegister[IDEX].output = stageRegister[IDEX].input;
	 stageRegister[EXMEM].output = stageRegister[EXMEM].input;
	 stageRegister[MEMWB].output = stageRegister[MEMWB].input;
 }

 void instructionToString(struct instruction *instruction, char *stringBuf) {
	 if(instruction->op == NOP) {
		 strcpy(stringBuf, "NOP");
	 }
	 else {
		 if(instruction->op == SUB || instruction->op == ADD) {
			 sprintf(stringBuf, "%s $%d, $%d, $%d", instruction->opString, instruction->dest, instruction->src1, instruction->src2);
		 }
		 else if(instruction->op == BNE || instruction->op == BEQ) {
			 sprintf(stringBuf, "%s $%d, $%d, %d", instruction->opString, instruction->src1, instruction->src2, instruction->offset);
		 }
		 else if(instruction->op == LW) {
			 sprintf(stringBuf, "%s $%d, %d($%d)", instruction->opString, instruction->dest, instruction->offset, instruction->src1);
		 }
		 else if(instruction->op == SW) {
			 sprintf(stringBuf, "%s $%d, %d($%d)", instruction->opString, instruction->src1, instruction->offset, instruction->src2);
		 }
		 else sprintf(stringBuf, "%s $%d, $%d, %d", instruction->opString, instruction->dest, instruction->src1, instruction->immediate);
	 }
 }

 char * forwardingFlagToString(struct comboevent *flag) {
	 if(flag->forwardingEvent > BRANCH) {
		if(flag->forwardingEvent == EXMEMtoIDsrc1) return "EXMEM.dest->ID.src1";
		else if(flag->forwardingEvent == EXMEMtoIDsrc1) return "EXMEM.dest->ID.src2";
		else if(flag->forwardingEvent == EXMEMtoEXsrc1) return "EXMEM.dest->EX.src1";
		else if(flag->forwardingEvent == EXMEMtoEXsrc2) return "EXMEM.dest->EX.src2";
		else if(flag->forwardingEvent == MEMWBtoIDsrc1) return "MEMWB.dest->ID.src1";
		else if(flag->forwardingEvent == MEMWBtoIDsrc2) return "MEMWB.dest->ID.src2";
		else if(flag->forwardingEvent == MEMWBtoEXsrc1) return "MEMWB.dest->EX.src1";
		else return "MEMWB.dest->EX.src1";
	 }
	 else return "NONE";
 }

 int parseTextFile(char *file, struct instruction *instrMemPtr, int *instructionCount, struct label_table *lTable) {
	 //Index keeps track of instructions going into instruction memory
	 *instructionCount = 0;
	 int labelTableIndex = 0;
	 int tokenCount = 0;

	 char *token;
	 //Open assembly text file READ-ONLY
	 FILE *txtFile = fopen(file, "r");
	 //Print error if text file cannot be opened
	 if(txtFile == NULL) {
		 printf("Unable to open file.\nMake sure that both the path and/or filename are correct\n");
		 return -1;
	 }
	 //Allocate a buffer to store one line at a time
	 char *lineBuffer = (char *)malloc(sizeof(char) * MAXCHARS);
	 //Read lines from the text file until EOF

	 while(fgets(lineBuffer, MAXCHARS, txtFile) != NULL) {
	 	//If the first character is # or \n, skip and go to next line
	 	if(*lineBuffer == '#' || *lineBuffer == '\n') continue;
	 	stringToUpperCase(lineBuffer);
	 	//Search for label
	 	if(strchr(lineBuffer, ':') != NULL) {
	 		//Extract the label
	 		token = strtok(lineBuffer, ":");
	 		//Copy label name to label look-up-table
	 		lTable[labelTableIndex].labelName = (char *)malloc((strlen(token) + 1) * sizeof(char));
	 		strcpy(lTable[labelTableIndex].labelName, token);
	 		//Associate instruction address with label name
	 		lTable[labelTableIndex].instrAddr = INSTR_BASE + (*instructionCount * BYTE_WIDTH);
	 		labelTableIndex++;
	 		token = strtok(NULL, " :\t");
	 		//strcpy(lineBuffer, token);
	 		//If the first char is '#' pretend it is a comment-only line and fetch new line
	 		if(*token == '#' || *token == '\n') continue;
	 	}
	 	//Separate new line char from current instruction line
	 	if(strchr(lineBuffer, '\n') != NULL) token = strtok(lineBuffer, "\n");
	 	strcpy(lineBuffer, token);
	 	//If the line of instruction has a comment, seperate the string into comment and non-comment portions
	 	if(strchr(lineBuffer, '#') != NULL) token = strtok(lineBuffer, "#");
	 	//Separate the above string into operand, destination and sources
	 	token = strtok(lineBuffer, " ,\t");

		 while(token != NULL) {
			 //Extract opcode
		 	if(tokenCount == 0) {
		 		strcpy(instrMemPtr[*instructionCount].opString, token);
		 		instrMemPtr[*instructionCount].op = opStringToInt(token);
		 		//NOP virtually carries no operands
		 		if(instrMemPtr[*instructionCount].op == NOP) 	break;
		 			//Get next token
		 	}
		 	//Extract destination
		 	else if(tokenCount == 1) {
		 		switch(instrMemPtr[*instructionCount].op) {
		 		case BEQ :
		 			instrMemPtr[*instructionCount].src1 = atoi(&token[1]);
		 			break;
		 		case BNE :
		 			instrMemPtr[*instructionCount].src1 = atoi(&token[1]);
		 			break;
		 		case SW :
		 			instrMemPtr[*instructionCount].src1 = atoi(&token[1]);
		 			break;
		 		default :
		 			instrMemPtr[*instructionCount].dest = atoi(&token[1]);
		 			break;
		 		}
		 	}
		 	//If we have an operand
		 	else if(tokenCount == 2) {
		 		//Arithmetic instructions
		 		if(instrMemPtr[*instructionCount].op <= SUB) {
		 			instrMemPtr[*instructionCount].src1 = atoi(&token[1]);
		 		}
		 		//Branch instructions
		 		else if(instrMemPtr[*instructionCount].op <= BNE) {
		 			instrMemPtr[*instructionCount].src2 = atoi(&token[1]);
		 		}
		 		//Memory Instructions
		 		else {
		 			if(strlen(token) == 4) {
		 				instrMemPtr[*instructionCount].offset = 0;
		 				if(instrMemPtr[*instructionCount].op == SW) instrMemPtr[*instructionCount].src2 = atoi(&token[2]);
		 				else instrMemPtr[*instructionCount].src1 = atoi(&token[2]);
		 			}
		 			else {
		 				instrMemPtr[*instructionCount].offset = atoi(&token[0]);
		 				if(instrMemPtr[*instructionCount].op == SW) instrMemPtr[*instructionCount].src2 = atoi(&token[3]);
		 				else instrMemPtr[*instructionCount].src1 = atoi(&token[3]);
		 			}
		 		}
		 	}
		 	//LW or SW should not reach here!
		 	else if(tokenCount == 3) {
		 		if(instrMemPtr[*instructionCount].op == BEQ || instrMemPtr[*instructionCount].op == BNE) {
		 			int i;
		 			//Search label look-up-table and get address of label
		 			for(i = 0; i < labelTableIndex; i++) {
		 				if(strcmp(lTable[i].labelName, token) == 0) {
		 					//Store offset from label into instruction
		 					instrMemPtr[*instructionCount].offset = ((lTable[i].instrAddr - INSTR_BASE) / BYTE_WIDTH) - (*instructionCount + 2);
		 					break;
		 				}
		 			}
		 		}
		 		else if(instrMemPtr[*instructionCount].op == ADDI) {
		 			instrMemPtr[*instructionCount].immediate = strtol(token, NULL, 0);
		 		}
		 	    else 	instrMemPtr[*instructionCount].src2 = atoi(&token[1]);
		 	}
		 	token = strtok(NULL, " ,\t");
		    tokenCount++;
	    }
	    *instructionCount += 1;
	    tokenCount = 0;
	}

    return 0;
}

