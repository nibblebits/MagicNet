OBJECTS= 
INCLUDES= -I ./ -I ../../lib/include
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ./main.c -g -L/usr/lib -lmagicnet ${OBJECTS} -o ./sender


clean:
	rm -rf ${OBJECTS}