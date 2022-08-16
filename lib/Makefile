OBJECTS= ./build/vector.o ./build/magicnet.o ./build/log.o ./build/network.o
INCLUDES= -I ./ -I ./include -I ./include/magicnet -I ./include/magicnet/vector
ADDITIONAL_FLAGS= -g -fPIC
all: ${OBJECTS}
	gcc -shared -o ./libmagicnet.so -pthread -g ${OBJECTS} 
	cp ./libmagicnet.so /usr/lib/libmagicnet.so 

./build/magicnet.o:./src/magicnet.c
	gcc ${INCLUDES} ./src/magicnet.c -c ${ADDITIONAL_FLAGS} -o ./build/magicnet.o 



./build/network.o:./src/network.c
	gcc ${INCLUDES} ./src/network.c -c ${ADDITIONAL_FLAGS} -o ./build/network.o 



./build/log.o:./src/log.c
	gcc ${INCLUDES} ./src/log.c -c ${ADDITIONAL_FLAGS} -o ./build/log.o 


./build/vector.o:./src/vector/vector.c
	gcc ${INCLUDES} ./src/vector/vector.c -c ${ADDITIONAL_FLAGS} -o ./build/vector.o 


clean:
	rm -rf ${OBJECTS}
	rm ./libmagicnet.so