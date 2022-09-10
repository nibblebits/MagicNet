OBJECTS= ./build/vector.o ./build/magicnet.o ./build/log.o ./build/network.o ./build/key.o ./build/sha256.o ./build/misc.o ./build/buffer.o
INCLUDES= -I ./ -I ./include -I ./include/magicnet -I ./include/magicnet/vector
ADDITIONAL_FLAGS= -g -fPIC
all: ${OBJECTS}
	gcc -pthread -lssl -lcrypto -lminiupnpc -pthread -lzip -shared -o ./libmagicnet.so   -g ${OBJECTS} 
	cp ./libmagicnet.so /usr/lib/libmagicnet.so 

./build/magicnet.o:./src/magicnet.c
	gcc ${INCLUDES} ./src/magicnet.c -c ${ADDITIONAL_FLAGS} -o ./build/magicnet.o 



./build/network.o:./src/network.c
	gcc ${INCLUDES} ./src/network.c -c ${ADDITIONAL_FLAGS} -o ./build/network.o 



./build/log.o:./src/log.c
	gcc ${INCLUDES} ./src/log.c -c ${ADDITIONAL_FLAGS} -o ./build/log.o 


./build/vector.o:./src/vector/vector.c
	gcc ${INCLUDES} ./src/vector/vector.c -c ${ADDITIONAL_FLAGS} -o ./build/vector.o 

./build/key.o:./src/key.c
	gcc ${INCLUDES} ./src/key.c -c ${ADDITIONAL_FLAGS} -o ./build/key.o 

./build/sha256.o:./src/sha256.c
	gcc ${INCLUDES} ./src/sha256.c -c ${ADDITIONAL_FLAGS} -o ./build/sha256.o 


./build/misc.o:./src/misc.c
	gcc ${INCLUDES} ./src/misc.c -c ${ADDITIONAL_FLAGS} -o ./build/misc.o 

./build/buffer.o:./src/buffer.c
	gcc ${INCLUDES} ./src/buffer.c -c ${ADDITIONAL_FLAGS} -o ./build/buffer.o 


clean:
	rm -rf ${OBJECTS}
	rm ./libmagicnet.so