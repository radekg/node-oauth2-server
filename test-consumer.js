var http = require("http")
	, net = require("net")
	, util = require("util")
	, qs = require("qs");

var postSetup = require("./test/post-setup").PostSetup;
	
var ps = new postSetup();
ps.runPostTest( ps.getPostData_refreshToken() );
//ps.runPostTest( ps.getPostData_authToken() );

var server = net.createServer(function (socket) {
  socket.write('Echo server\r\n');
  socket.pipe(socket);
});

server.listen(1337, '127.0.0.1');