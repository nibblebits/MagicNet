OBJECTS= 
INCLUDES= -I ./
ADDITIONAL_FLAGS= -g 
all: ${OBJECTS}
	gcc ${INCLUDES} ./main.c -L/usr/lib -lmagicnet ${OBJECTS} -o ./listener


clean:
	rm -rf ${OBJECTS}