OBJECTS= 
INCLUDES= -I ./ -I ../../lib/include
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./main.c -L/usr/lib -lmagicnet ${OBJECTS} -o ./listener


clean:
	rm -rf ${OBJECTS}