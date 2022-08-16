OBJECTS= 
INCLUDES= -I ./ -I../lib/include
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ./main.c -L/usr/lib -lmagicnet ${OBJECTS} -o ./server


clean:
	rm -rf ${OBJECTS}