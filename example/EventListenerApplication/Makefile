OBJECTS= 
INCLUDES= -I ./ -I ../../lib/include
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./main.c -L/usr/lib -lmagicnet ${OBJECTS} -o ./event_listener


clean:
	rm -rf ${OBJECTS}