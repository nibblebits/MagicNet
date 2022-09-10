OBJECTS= 
INCLUDES= -I ./ -I ../../lib/include
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./main.c -lmagicnet  -lcrypto -lminiupnpc -pthread -lzip  ${OBJECTS} -o ./listener


clean:
	rm -rf ${OBJECTS}