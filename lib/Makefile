OBJECTS= ./build/vector.o ./build/magicnet.o ./build/events.o ./build/init.o ./build/block.o ./build/log.o ./build/network.o ./build/peer.o ./build/signaling.o ./build/cdownloader.o ./build/database.o ./build/wallet.o ./build/key.o ./build/sha256.o ./build/misc.o ./build/buffer.o
INCLUDES= -I ./ -I ./include -I ./include/magicnet -I ./include/magicnet/vector
ADDITIONAL_FLAGS= -g -fPIC
all: ${OBJECTS}
	gcc  -shared -o ./libmagicnet.so  ${OBJECTS} -Wl,--as-needed -lsqlite3 -pthread -lssl -lcrypto -fpic -lminiupnpc -pthread -lzip -lc  -g
	cp ./libmagicnet.so /usr/lib/libmagicnet.so 

./build/magicnet.o:./src/magicnet.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS}  ./src/magicnet.c -c -o ./build/magicnet.o 

./build/events.o:./src/events.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS}  ./src/events.c -c -o ./build/events.o 


./build/init.o:./src/init.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS}  ./src/init.c -c -o ./build/init.o 

./build/block.o:./src/block.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS}  ./src/block.c -c -o ./build/block.o 


# Compile the peer.c
./build/peer.o:./src/peer.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/peer.c -c -o ./build/peer.o

./build/network.o:./src/network.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/network.c -c -o ./build/network.o 

./build/signaling.o:./src/signaling.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/signaling.c -c -o ./build/signaling.o 


./build/cdownloader.o:./src/cdownloader.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/cdownloader.c -c -o ./build/cdownloader.o 

./build/database.o:./src/database.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/database.c -c -o ./build/database.o 

./build/wallet.o:./src/wallet.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/wallet.c -c -o ./build/wallet.o 

./build/log.o:./src/log.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS}  ./src/log.c -c -o ./build/log.o 


./build/vector.o:./src/vector/vector.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS}  ./src/vector/vector.c -c  -o ./build/vector.o 

./build/key.o:./src/key.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/key.c -c  -o ./build/key.o 

./build/sha256.o:./src/sha256.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/sha256.c -c -o ./build/sha256.o 


./build/misc.o:./src/misc.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/misc.c -c  -o ./build/misc.o 

./build/buffer.o:./src/buffer.c
	gcc ${INCLUDES} ${ADDITIONAL_FLAGS} ./src/buffer.c -c -o ./build/buffer.o 


clean:
	rm -rf ${OBJECTS}
	rm ./libmagicnet.so