OBJECTS= 
INCLUDES= -I ./ -I ../../lib/include
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./main.c -L/usr/lib -lmagicnet ${OBJECTS} -o ./blockchain_writer


clean:
	rm -rf ${OBJECTS}