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
				oauth2.storeAuthCode = function( code, client_id, expiry ) {
					if ( typeof expiry != "number" ) {
						expiry = oauth2.expiryDefault;
					}
					var expiryDate = new Date( (new Date()).getTime() + expiry );
					mongodClient.collection("authCodes", function(err, collection) {
						collection.insert( { auth_code: code, client_id: client_id, expiries: expiryDate.getTime() } );
					});
				};
				oauth2.timer_authCodeHandler = function( runAt ) {
					mongodClient.collection("authCodes", function(err,collection) {
						collection.remove( { expires: { $lt: runAt } } )
					});
				};
				
				oauth2.getOauth2InputBySessionLoginCode = function( code, callback ) {
					mongodClient.collection("sessionLoginCodes", function(err, collection) {
						collection.find( { code: code }, function(error,cursor) {
							cursor.toArray( function(err,arr) {
								if ( arr.length == 0 ) {
									callback( null );
								} else {
									var item = arr[0];
									process.nextTick( function() {
										mongodClient.collection("sessionLoginCodes", function( err, n_collection ) {
											item.expires = (new Date() + item.expiresBy);
											n_collection.update( { code: item.code, item } );
										});
									} );
									callback(item);
								}
							});
						});
					});
				};
				oauth2.storeSessionLoginCode = function( code, state, expiry ) {
					if ( typeof expiry != "number" ) {
						expiry = oauth2.sessionLoginExpiryDefault;
					}
					var expiryDate = new Date( (new Date()).getTime() + expiry );
					mongodClient.collection("sessionLoginCodes", function(err, collection) {
						collection.insert( { code: code, stateObject: state, expiries: expiryDate.getTime(), expiresBy: expiry } );
					});
				};
				oauth2.timer_sessionLoginCodeHandler = function( runAt ) {
					mongodClient.collection("sessionLoginCodes", function(err,collection) {
						collection.remove( { expires: { $lt: runAt } } )
					});
				};
				
				oauth2.updateUserPrivileges = function( user_id, client_id, scopes ) {
					this.getUserAccountBy( { id: user_id }, function( account ) {
						if ( account != null ) {
							if ( account.authorized == null || account.authorized == undefined ) {
								account.authorized = {};
							}
							account.authorized[ client_id ] = scopes;
							process.nextTick(function() {
								mongodClient.collection("users", function( err, collection ) {
									collection.update( { id: user_id }, account );
								});
							});
						}
					} );
				};
				oauth2.getUserAccountBy = function( params, callback ) {
					mongodClient.collection("users", function(err, collection) {
						collection.find( params, function(err, cursor) {
							cursor.toArray( function( err, arr ) {
								if ( arr.length == 0 ) {
									callback( null );
								} else {
									callback( arr[0] );
								}
							} );
						});
					});
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

function noSessionCode( res ) {
	res.writeHead(401, "Session expired");
	res.end();
}

var app = express.createServer();
app.set('view options', { layout: false });
app.set('view engine', 'jade');
app.use(express.static(__dirname + '/public'));
app.use(express.cookieParser());
app.use(express.bodyParser());

app.get("/", function(req,res) {
	res.render("root", { encodedUrl: encodeURIComponent("http://testoauth2:2800/oauth2callback") });
});

app.get("/oauth2/logout", function(req,res) {
	res.clearCookie("logged_in");
	res.redirect("/");
});

app.get("/oauth2/login", function(req,res) {
	
	var sessionCode = req.param("ses", null);
	if ( sessionCode == null ) {
		return noSessionCode( res );
	}
	
	oauth2.getOauth2InputBySessionLoginCode( oauth2.fixString( sessionCode ), function( sessionData ) {
		if ( sessionData == null ) {
			res.writeHead(401, "Session expired " + oauth2.fixString( sessionCode ) );
			res.end();
		} else {
			var error = req.cookies.error;
			res.clearCookie("error")
			res.render("login", {
				res: res
				, sessionCode: sessionCode
				, error: error
			});
		}
	} );
	
});

app.post("/oauth2/do-login", function(req,res) {
	
	var sessionCode = req.param("ses", null);
	if ( sessionCode == null ) {
		return noSessionCode( res );
	}
	
	oauth2.getOauth2InputBySessionLoginCode( oauth2.fixString( sessionCode ), function( sessionData ) {
		if ( sessionData == null ) {
			res.writeHead(401, "Session expired " + oauth2.fixString( sessionCode ) );
			res.end();
		} else {
			// TODO: params should be loaded from an external function
			oauth2.getUserAccountBy( { username: req.param("username", null), password: req.param("password", null) }, function( account ) {
				if ( account != null ) {
					res.cookie("logged_in", account.username);
					res.redirect( "/oauth2/scopes?ses=" + oauth2.fixString( sessionCode ) );
				} else {
					res.cookie( "error", "Could not log you in." );
					res.redirect("/oauth2/login?ses=" + oauth2.fixString( sessionCode ));
				}
			} );
		}
	});
	
});

app.get("/oauth2/scopes", function(req,res) {
	
	if ( req.cookies.logged_in == null ) {
		res.redirect("/oauth2/login");
		res.end();
		return;
	}
	
	var sessionCode = req.param("ses", null);
	if ( sessionCode == null ) {
		return noSessionCode( res );
	}
	
	oauth2.getOauth2InputBySessionLoginCode( oauth2.fixString( sessionCode ), function( sessionData ) {
		if ( sessionData == null ) {
			res.writeHead(401, "Session expired");
			res.end();
		} else {
			oauth2.clientIdLookup( sessionData.stateObject.client_id, function(clientApp) {
				if ( clientApp == null ) {
					res.writeHead(400, "Client ID invalid");
					res.end();
				} else {

					var requestedScopes = sessionData.stateObject.scope.split(" ");
					var scopes = [];
					for ( var i=0; i<requestedScopes.length; i++ ) {
						var aScopeName = oauth2.getScopeName( requestedScopes[i] );
						if ( aScopeName == null ) {
							// TODO: if redirect_uri specified, send back
							res.writeHead(400, "invalid_scope: " + requestedScopes[i]);
							res.end();
							return;
						} else {
							scopes.push( { scope: requestedScopes[i], name: aScopeName } );
						}
					}
					res.render("scopes", {
						scopes: scopes
						, clientApp: clientApp
						, sessionCode: oauth2.fixString( sessionCode )
					});
				}
			});
		}
	});
	
});
app.get("/oauth2/do-scopes", function(req,res) {
	
	if ( req.cookies.logged_in == null ) {
		res.redirect("/oauth2/login");
		res.end();
		return;
	}
	
	var sessionCode = req.param("ses", null);
	if ( sessionCode == null ) {
		return noSessionCode( res );
	}
	var accessStatus = req.param("access_status", null);
	if ( accessStatus !== "allow" && accessStatus !== "deny" ) {
		res.writeHead(400, "Bad request");
		req.end();
		return;
	}
	
	oauth2.getOauth2InputBySessionLoginCode( oauth2.fixString( sessionCode ), function( sessionData ) {
		if ( sessionData == null ) {
			res.writeHead(401, "Session expired");
			res.end();
		} else {
			// check if user has allowed or denied the access:
			if ( accessStatus == "allow" ) {
				var authCode = oauth2.generateAuthCode( sessionData.stateObject.client_id );
				oauth2.storeAuthCode( oauth2.fixString( authCode ), sessioData.stateObject.client_id );
				oauth2.updateUserPrivileges(
					req.cookies.logged_in
					, sessionData.stateObject.client_id
					, sessionData.stateObject.scope.split(" ") );
				// TODO: redirect the user to the redirect_uri
				res.writeHead(200, authCode);
			} else if ( accessStatus == "deny" ) {
				// TODO: redirect the user to the redirect_uri
				res.writeHead(400, "access_denied: User denied");
			}
		}
	});
		
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
			// TODO: if redirect_uri specified, send back
			res.writeHead(400, "unauthorized_client: Client ID invalid");
			res.end();
		} else {
			
			if ( req.cookies.logged_in != null ) {
				
				// get account by user id:
				// check if the user authorized the app and all scopes requested
					// if true - generate the code and send back
					// otherwise - show scopes page
				
			} else {
				var loginSessionCode = oauth2.generateLoginSessionCode(client_id);
				oauth2.storeSessionLoginCode( loginSessionCode, {
					client_id: client_id
					, redirect_uri: redirect_uri
					, response_type: response_type
					, scope: scope
					, state: state } );
				res.redirect("/oauth2/login?ses=" + loginSessionCode);
			}
			
		}
	} );
	
});

app.get("/oauth2/token", function(req,res) {
	
});

app.listen(3000);