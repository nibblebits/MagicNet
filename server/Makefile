OBJECTS= 
INCLUDES= -I ./ -I../lib/include
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ./main.c -L/usr/lib -lmagicnet  -lcrypto -lminiupnpc -pthread -lzip  -g ${OBJECTS} -o ./server


clean:
	rm -rf ${OBJECTS}