all:
	cd ./lib && $(MAKE) all
	cd ./server && $(MAKE) all
	cd ./example/MessageListenerApplication && $(MAKE) all
	cd ./example/MessageSenderApplication && $(MAKE) all
	cd ./example/BlockchainWriterApplication && $(MAKE) all
	cd ./example/MoneyTransferApplication && $(MAKE) all
	cd ./example/EventListenerApplication && $(MAKE) all
	cd ./example/CouncilCertificateApplication && $(MAKE) all



clean:
	cd ./lib && $(MAKE) clean
	cd ./server && $(MAKE) clean
	cd ./example/MessageListenerApplication && $(MAKE) clean
	cd ./example/MessageSenderApplication && $(MAKE) clean
	cd ./example/BlockchainWriterApplication && $(MAKE) clean
	cd ./example/MoneyTransferApplication && $(MAKE) clean
	cd ./example/EventListenerApplication && $(MAKE) clean
	cd ./example/CouncilCertificateApplication && $(MAKE) clean


