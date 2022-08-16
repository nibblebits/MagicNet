all:
	cd ./lib && $(MAKE) all
	cd ./server && $(MAKE) all
#	cd ./example/ChatApplication && $(MAKE) all


clean:
	cd ./lib && $(MAKE) clean
	cd ./server && $(MAKE) clean

#	cd ./example/ChatApplication && $(MAKE) clean

