OBJECTS= 
INCLUDES= -I ./ -I ../../lib/include
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ./main.c -g -lmagicnet -pthread -lssl -lcrypto -lminiupnpc -pthread -lzip  ${OBJECTS}  -o ./sender


clean:
	rm -rf ${OBJECTS}