var http = require("http")
	, net = require("net")
	, util = require("util")
	, qs = require("qs");

function PostSetup() {
	
	this.getPostData_refreshToken = function() {
		var post_data = qs.stringify({
			'refresh_token' : 'r1BIu45gQyR5zG4h2wVcfAzigMg='
			, 'client_id': 'O0-rdIQGiKqihdwE9-DqudbWY'
			, 'client_secret': 'iumuaEdrISivQ2YRZFjQ45x9QdqtZgKmTrTB'
			, 'grant_type' : 'refresh_token' });
		return post_data;
	};
	
	this.getPostData_authToken = function() {
		var post_data = qs.stringify({
			'code' : 'N7NahsHxAqwiRn4Fxs6yglt0ZEU='
			, 'client_id': 'O0-rdIQGiKqihdwE9-DqudbWY'
			, 'client_secret': 'iumuaEdrISivQ2YRZFjQ45x9QdqtZgKmTrTB'
			, 'grant_type' : 'authorization_code' });
		return post_data;
	};
	
	this.runPostTest = function( data ) {
		// An object of options to indicate where to post to
		var post_options = {
			host: 'localhost',
			port: 3000,
			path: '/oauth2/token',
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Content-Length': data.length
			}
		};

		var post_req = http.request(post_options, function(res) {
			res.on('data', function (chunk) {
				util.puts(chunk);
			});
			res.on('end', function () {
				process.exit();
			});
		});
		
		post_req.on('error', function( err ) {
			util.puts("Errror" + JSON.stringify( err ));
		});
		post_req.on('end', function( ) {
			util.puts("Disconnected");
		});
		
		post_req.write(data);
		post_req.end();
	};
	
};

exports.PostSetup = PostSetup;