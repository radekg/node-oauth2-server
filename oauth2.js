var express = require("express")
	, util = require("util")
	, qs = require("qs")
	, url = require("url")
	, OAuth2Server = require("./server/oauth2-server").OAuth2Server
	, Db = require('mongodb').Db
	, Connection = require('mongodb').Connection
	, Server = require('mongodb').Server;


// MONGO SETUP:
var MONGOD = {
	CONNECTION_STRING: "",
	CONNECTION_PARSED: {},
	REQUIRES_AUTH: false,
	USERNAME: "",
	PASSWORD: "" };
MONGOD.CONNECTION_STRING = process.env.MONGOLAB_URI || "mongod://127.0.0.1:27017/oauth2-server-test";
MONGOD.CONNECTION_PARSED = url.parse( MONGOD.CONNECTION_STRING );
if ( MONGOD.CONNECTION_PARSED.auth ) {
	MONGOD.REQUIRES_AUTH = true;
	var authParts = MONGOD.CONNECTION_PARSED.auth.split(":");
	MONGOD.USERNAME = authParts[0];
	MONGOD.PASSWORD = authParts[1];
}
var mongodClient = new Db(
	MONGOD.CONNECTION_PARSED.pathname.substr(1, MONGOD.CONNECTION_PARSED.pathname.length )
	, new Server(
		MONGOD.CONNECTION_PARSED.hostname+""
		, parseInt(MONGOD.CONNECTION_PARSED.port)
		, {} ) );
mongodClient.open(function(err, p_client) {
	if ( MONGOD.REQUIRES_AUTH ) {
		p_client.authenticate( MONGOD.USERNAME, MONGOD.PASSWORD, function( err, collection ) {
			if ( err != null ) {
				sys.puts("FATAL: MONGOD - can't authenticate");
			} else {
				setupOAuth2Server();
			}
		} );
	} else {
		setupOAuth2Server();
	}
});

var oauth2 = null;
function setupOAuth2Server() {
	util.puts("Setting up OAuth2, connected to mongod, reading scopes for this app");
	mongodClient.collection("scopes", function(err, collection) {
		collection.find({}, function(err, cursor) {
			cursor.toArray( function(err, arr) {
				
				util.puts( " -> OAuth2 server initialized with scopes: " + JSON.stringify( arr ) );
				
				oauth2 = new OAuth2Server({ scopes: arr });
				oauth2.accountLogin = function( username, password, callback ) {
					mongodClient.collection("users", function(err, collection) {
						collection.find( { username: username }, function(err, cursor) {
							cursor.toArray( function( err, arr ) {
								if ( arr.length == 0 ) {
									callback( null );
								} else {
									if ( arr[0].password == password ) {
										callback( arr[0] );
									} else {
										callback( null );
									}
								}
							} );
						});
					});
				};
				oauth2.accountAllowedScopes = function( account_id, client_id ) {
				};
				oauth2.clientIdLookup = function(client_id, callback) {
					mongodClient.collection("apps", function(err, collection) {
						collection.find( { client_id: client_id }, function(err, cursor) {
							cursor.toArray( function( err, arr ) {
								if ( arr.length == 0 ) {
									callback( null );
								} else {
									callback( arr[0] );
								}
							} );
						} );
					} );
				};
				
			});
		});
	});
}

var app = express.createServer();
app.use(express.cookieParser());
app.use(express.bodyParser());

app.get("/", function(req,res) {
	res.send("<a href='http://localhost:3000/oauth2/auth?response_type=code&client_id=O0-rdIQGiKqihdwE9-DqudbWY&redirect_uri=" + encodeURIComponent("http://testoauth2:2800/oauth2callback") + "&scope=read edit new account'>do the test</a>");
});

app.get("/oauth2/logout", function(req,res) {
	res.clearCookie("logged_in");
	res.redirect("/");
});

app.get("/oauth2/login", function(req,res) {
	
	var sessionCode = req.param("ses", null);
	if ( sessionCode == null ) {
		res.writeHead(401, "Session expired");
		res.end();
		return;
	}
	
	if ( oauth2.isLoginSessionCodeValid( oauth2.fixString( sessionCode ) ) ) {
		var error = req.cookies.error;
		var html = "<form action='/oauth2/do-login' method='post'>";
		if ( error != null ) {
			html += "There was an error: " + error;
			res.clearCookie("error");
		}
		html += "<input type='hidden' name='ses' value='" + sessionCode + "' /><br/>";
		html += "Username: <input type='text' name='username' /><br/>";
		html += "Password: <input type='password' name='password' /><br/>";
		html += "<input type='submit' value='Login' />";
		html += "</form>";
		res.send(html);
	} else {
		res.writeHead(401, "Session expired " + oauth2.fixString( sessionCode ) );
		res.end();
	}
});

app.post("/oauth2/do-login", function(req,res) {
	var sessionCode = req.param("ses", null);
	if ( sessionCode == null ) {
		res.writeHead(401, "Session expired");
		res.end();
		return;
	}
	if ( oauth2.isLoginSessionCodeValid( oauth2.fixString( sessionCode ) ) ) {
		oauth2.accountLogin( req.param("username", null), req.param("password", null), function( account ) {
			if ( account != null ) {
				res.cookie("logged_in", account.id);
				res.redirect( "/oauth2/scopes?ses=" + sessionCode );
			} else {
				res.cookie( "error", "Could not log you in." );
				res.redirect("/oauth2/login?ses=" + sessionCode);
			}
		} );
	} else {
		res.writeHead(401, "Session expired " + oauth2.fixString( sessionCode ));
		res.end();
	}
});
app.get("/oauth2/scopes", function(req,res) {
	var sessionCode = req.param("ses", null);
	if ( sessionCode == null ) {
		res.writeHead(401, "Session expired");
		res.end();
		return;
	}
	
	sessionCode = oauth2.fixString( sessionCode );
	
	if ( oauth2.isLoginSessionCodeValid( sessionCode ) ) {
		var data = oauth2.getOauth2InputBySessionLoginCode( sessionCode );
		
		oauth2.clientIdLookup( data.client_id, function(clientApp) {
			if ( clientApp == null ) {
				res.writeHead(400, "Client ID invalid");
				res.end();
			} else {
				
				var html = "<strong>" + clientApp.name + "</strong> is requesting for the following permissions:";
				html += "<ul>";
				
				var requestedScopes = data.scope.split(" ");
				var scopes = [];
				for ( var i=0; i<requestedScopes.length; i++ ) {
					var aScopeName = oauth2.getScopeName( requestedScopes[i] );
					if ( aScopeName == null ) {
						// TODO: if redirect_uri specified, send back
						res.writeHead(400, "invalid_scope: " + requestedScopes[i]);
						res.end();
						return;
					} else {
						html += "<li>" + aScopeName + "</li>";
					}
				}
				
				html += "</ul>";
				html += "<form action='/oauth2/do-scopes' method='post'>";
				html += "<input type='hidden' name='access_status' value='allow' />";
				html += "<input type='button' value='Allow access' />";
				html += "</form>";
				
				html += "<form action='/oauth2/do-scopes' method='post'>";
				html += "<input type='hidden' name='access_status' value='deny' />";
				html += "<input type='submit' value='No, thanks' />";
				html += "</form>";
				res.send( html );
			}
		});
		
	} else {
		res.writeHead(401, "Session expired");
		res.end();
	}
	
});
app.get("/oauth2/do-scopes", function(req,res) {
	var sessionCode = req.param("ses", null);
	if ( sessionCode == null ) {
		res.writeHead(401, "Session expired");
		res.end();
		return;
	}
});

app.get("/oauth2/auth", function(req,res) {
	
	var redirect_uri = req.param("redirect_uri", null);
	var response_type = req.param("response_type", null);
	var client_id = req.param("client_id", null);
	var scope = req.param("scope", null);
	var state = req.param("state", null);
	
	if ( client_id != null ) client_id = oauth2.fixString( client_id );
	
	oauth2.clientIdLookup( client_id, function(clientApp) {
		if ( clientApp == null ) {
			res.writeHead(400, "Client ID invalid");
			res.end();
		} else {
			
			if ( req.cookies.logged_in != null ) {
				if ( scope == null ) {
					scope = [];
				}
				
			} else {
				var loginSessionCode = oauth2.generateLoginSessionCode(client_id);
				oauth2.doLoginSessionCodeStorage( client_id, loginSessionCode, redirect_uri, response_type, scope, state );
				res.redirect("/oauth2/login?ses=" + loginSessionCode);
			}
			
		}
	} );
	
	/*
	var authResponse = oauth2.processAuth(
		response_type
		, client_id
		, redirect_uri
		, scope
		, state );
	
	if ( redirect_uri != null ) {
		res.header("Location", redirect_uri + "?" + qs.stringify(authResponse));
	} else {
		res.send( JSON.stringify( authResponse ) );
	}
	*/
});

app.listen(3000);