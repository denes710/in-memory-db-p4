# In-network database P4
You can find a deeper documentation about the protocol in the `imn.p4` file. Also, you can use of the `--help` for getting more information about the `inm.py` application.
## Compiling and running
Make command compiles the p4 file and runs the minnit with the defined topology from the inm directory .
```
p4@p4:~/inm$ make
```
## Sending packets
You can open a host terminal from the mininet terminal. By default, there are two hosts. Their names are `h1` and `h2`.
```
mininet> xterm h1
```
You can run the application for communicating with the switch and test the functionalities of the implemented protocol.
```
p4@p4:~/inm$ python3 inm.py --src_num "00:05:00:00:00:00"
```
