#KNOWN BUGS

1. Issue where the listener application is not able to receive packets
from other clients on the internet, this bug is since the sharedptr implementation
no multi-threading problems seem to be present.

2. MessageSend/Listen is slower than it should be find out why.

3. Relay packet to client might not be safe thread wise..
