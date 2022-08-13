OBJECTS=./build/magicnet.o
INCLUDES= -I ./ -I ./includes
ADDITIONAL_FLAGS= -g -fPIC
all: ${OBJECTS}
	gcc -shared -o ./libmagicnet.so -g ${OBJECTS} 
	cp ./libmagicnet.so /usr/lib/libmagicnet.so

./build/magicnet.o:./magicnet.c
	gcc ${INCLUDES} ./magicnet.c -c ${ADDITIONAL_FLAGS} -o ./build/magicnet.o 


clean:
	rm -rf ${OBJECTS}
	rm ./libmagicnet.so