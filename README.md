#Magic Net

Magic net is a decentralized network framework where every peer is a contributor. The network its self accepts all blocks as valid even fake ones it then determines
the active chain (real chain) after some time by taking into account how many verified blocks have been created on a given block chain.
This design means that if an attacker was to some how trick the network as soon as he expells his resources due to the cost of the attack. The network will naturally 
revert back to the real chain in given time. This is the security mechnism that keeps the network secure.

This is experimental at this point in time and uses brand new concepts that founder Daniel McCarthy has invented. 

Currently the system can create new blocks with ease, keep clients in sync when they go offline for some period of time. When the client comes back online the updated
chains are automatically downloaded. 

Their are some current issues when receving blocks in the wrong order the system mistakingly creates a new blockchain as it assumes that the chain
has forked/split into seperate chains. It will be a few months until their is a fully functioning prototype.

Also planned is a 1 to 1 peer connection protocol that will allow applications that use the decentralized framework to connect to a single client of their
choosing. This would be handy for chat applications where one peer wants to send messages to another. This peer connection protocol will not rely on ip addresses
or ports. You will instead make a connection via their public key. The network will then automatically find a way to communicate with that client.

Possible ways to connect are:
1. Connection directly to the peer (problematic for computers without UPNP or port forwarding)
2. Middle man (Someone on the network will be selected to relay packets from peer to peer

This is an exciting project, with many trials that stem away from traditional blockchain ideologies. Blockchain and decentralized technology is still a free for all at
this time. Nobody knows the best way to do things yet because decentralized tech has only recently started to kick off.

Theirs still a lot of mistakes and rewards to discover in this field. We are at the stone wheel. Perhaps this project will help change things.
Star it!
