# 2019-Python-crol453
Chatter Social Media Client
## Dependencies
Uses cherrypy for running and managing webserver, pynacl for encryption
-cherrypy
-pynacl

## Usage
### Config File
In the /cfg directory, there should be a file called ip.ini. If there is not, create one, as the server will not run without it.

In this file, you will need to set your connection address and location. This is stored im json format text.
Note that you also need to include the port number at the end of the adress. This is hard coded to 10000, but you can change this
yourself in the main.py file.

### Running
To run the client, simply run the main.py file.


