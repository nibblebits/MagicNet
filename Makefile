all:
	cd ./lib && $(MAKE) all
	cd ./example/ChatApplication && $(MAKE) all


clean:
	cd ./lib && $(MAKE) clean
	cd ./example/ChatApplication && $(MAKE) clean

