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
	mongodClient.collection("scopes", function(err, collection) {
		collection.find({}, function(err, cursor) {
			cursor.toArray( function(err, arr) {
				
				util.puts( " -> OAuth2 server initialized with scopes: " + JSON.stringify( arr ) );
				
				oauth2 = new OAuth2Server({ scopes: arr });
				oauth2.storeAuthCode = function( code, state, expiry ) {
					if ( typeof expiry != "number" ) {
						expiry = oauth2.expiryDefault;
					}
					var expiryDate = new Date( (new Date()).getTime() + expiry );
					mongodClient.collection("authCodes", function(err, collection) {
						collection.insert( { auth_code: code, state: state, expiries: expiryDate.getTime() } );
					});
				};
				oauth2.getOAuth2InputByAuthCode = function( code, callback ) {
					mongodClient.collection("authCodes", function(err,collection) {
						collection.find( { auth_code: code }, function( err, cursor ) {
							cursor.toArray( function(err, arr) {
								if ( arr.length == 0 ) {
									callback( null );
								} else {
									var item = arr[0];
									callback(item.state);
								}
							} );
						} );
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
											n_collection.update( { code: item.code }, item );
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
					this.getUserAccountBy( { username: user_id }, function( account ) {
						if ( account != null ) {
							util.puts( "Account is not null " + account.id );
							if ( account.authorized == null || account.authorized == undefined ) {
								account.authorized = {};
							}
							if ( scopes == null ) {
								delete account.authorized[ client_id ];
							} else {
								account.authorized[ client_id ] = scopes;
							}
							process.nextTick(function() {
								mongodClient.collection("users", function( err, collection ) {
									collection.update( { username: user_id }, account );
								});
							});
						}
					} );
				};
				oauth2.assignUserOAuth2Session = function( user_id, auth_code, client_id ) {
					mongodClient.collection("oauth2Sessions", function(err, collection) {
						collection.find( { user_id: user_id, client_id: client_id }, function( err, cursor ) {
							cursor.toArray( function(err, arr) {
								if ( arr.length == 0 ) {
									var refreshToken = oauth2.generateRefreshToken( client_id );
									collection.insert( { user_id: user_id, auth_code: auth_code, client_id: client_id, refresh_token: refreshToken } );
								} else {
									var item = arr[0];
									item.auth_code = auth_code;
									collection.update( { user_id: user_id, client_id: client_id }, item );
								}
							} );
						} );
					});
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
				oauth2.clientAppsLookup = function(client_ids, callback) {
					mongodClient.collection("apps", function(err, collection) {
						collection.find( { client_id: { $in: client_ids } }, function(err, cursor) {
							cursor.toArray( function( err, arr ) {
								if ( arr.length == 0 ) {
									callback( null );
								} else {
									callback( arr );
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
	var authorizedApps = [];
	var loggedIn = req.cookies.logged_in != null;
	if ( loggedIn ) {
		oauth2.getUserAccountBy( { username: req.cookies.logged_in }, function(account) {
			if ( account != null ) {
				var client_ids = [];
				if ( account.authorized != null && account.authorized != undefined ) {
					for ( var key in account.authorized ) {
						client_ids.push( key );
					}
				}
				oauth2.clientAppsLookup( client_ids, function( apps ) {
					res.render("root", {
						encodedUrl: encodeURIComponent("http://testoauth2:2800/oauth2callback")
						, loggedIn: loggedIn
						, authorizedApps: apps
						, error: null
					});
				});
			} else {
				res.render("root", {
					encodedUrl: encodeURIComponent("http://testoauth2:2800/oauth2callback")
					, loggedIn: loggedIn
					, authorizedApps: []
					, error: "no_account"
				});
			}
		});
	} else {
		res.render("root", {
			encodedUrl: encodeURIComponent("http://testoauth2:2800/oauth2callback")
			, loggedIn: loggedIn
			, authorizedApps: []
			, error: null
		});
	}
});

app.get("/oauth2/logout", function(req,res) {
	res.clearCookie("logged_in", { path: "/" });
	res.redirect("/");
});

app.get("/oauth2/deauthorize", function(req,res) {
	if ( req.cookies.logged_in == null ) {
		res.redirect("/oauth2/login");
		res.end();
		return;
	}
	oauth2.updateUserPrivileges( req.cookies.logged_in, req.param("client_id", null), null);
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
	});
	
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
			oauth2.getUserAccountBy( { username: req.param("username", null), password: req.param("password", null) }, function( account ) {
				if ( account != null ) {
					res.cookie("logged_in", account.username, { path: "/" });
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
					res.writeHead(400, "invalid_request: Client ID invalid");
					res.end();
				} else {
					var requestedScopes = sessionData.stateObject.scope.split(" ");
					var scopes = [];
					for ( var i=0; i<requestedScopes.length; i++ ) {
						scopes.push( { scope: requestedScopes[i], name: oauth2.getScopeName( requestedScopes[i] ) } );
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
app.post("/oauth2/do-scopes", function(req,res) {
	
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
				oauth2.storeAuthCode( oauth2.fixString( authCode ), sessionData.stateObject );
				oauth2.updateUserPrivileges(
					req.cookies.logged_in
					, sessionData.stateObject.client_id
					, sessionData.stateObject.scope.split(" ") );
				oauth2.assignUserOAuth2Session(
					req.cookies.logged_in
					, oauth2.fixString( authCode )
					, sessionData.stateObject.client_id );
				
				if ( sessionData.stateObject.redirect_uri != null ) {
					var _url = sessionData.stateObject.redirect_uri + "?";
					if ( sessionData.stateObject.state != null ) {
						_url += "&state=" + state;
					}
					_url += "&code=" + authCode;
					res.redirect( _url );
					res.end()
				} else {
					oauth2.sendResponse( sessionData.stateObject, { code: authCode }, res );
					res.end();
				}
				
			} else if ( accessStatus == "deny" ) {
				oauth2.sendErrorResponse( sessionData.stateObject, { error: "access_denied", error_description: "User denied." }, res );
				res.end();
			}
		}
	});
		
});

app.get("/oauth2/auth", function(req,res) {
	
	var stateObject = {
		client_id: req.param("client_id", null)
		, redirect_uri: req.param("redirect_uri", null)
		, response_type: req.param("response_type", null)
		, scope: req.param("scope", null)
		, state: req.param("state", null) };
	var validationStatus = oauth2.validateAuthRequest( stateObject, req.header("Referer") );
	if ( validationStatus.error != null ) {
		oauth2.sendErrorResponse( stateObject, validationStatus, res );
		res.end();
		return;
	}
	
	stateObject.client_id = oauth2.fixString( stateObject.client_id );
	
	oauth2.clientIdLookup( stateObject.client_id, function(clientApp) {
		if ( clientApp == null ) {
			oauth2.sendErrorResponse( stateObject, { error: "unauthorized_client", error_description: "Client ID invalid" }, res );
			res.end();
		} else {
			if ( req.cookies.logged_in == undefined ) {
				var loginSessionCode = oauth2.generateLoginSessionCode(stateObject.client_id);
				oauth2.storeSessionLoginCode( loginSessionCode, stateObject );
				res.redirect("/oauth2/login?ses=" + loginSessionCode);
			} else {
				oauth2.getUserAccountBy( { username: req.cookies.logged_in }, function( account ) {
					if ( account != null ) {
						if ( account.authorized == null || account.authorized == undefined ) {
							account.authorized = {};
						}
						if ( account.authorized[ stateObject.client_id ] == null || account.authorized[ stateObject.client_id ] == undefined ) {
							var loginSessionCode = oauth2.generateLoginSessionCode(stateObject.client_id);
							oauth2.storeSessionLoginCode( loginSessionCode, stateObject );
							res.redirect("/oauth2/scopes?ses=" + loginSessionCode);
						} else {
							var authCode = oauth2.generateAuthCode( stateObject.client_id );
							oauth2.storeAuthCode( oauth2.fixString( authCode ), stateObject );
							oauth2.sendResponse( stateObject, { code: authCode }, res )
							res.end();
						}
					} else {
						oauth2.sendErrorResponse( stateObject, { error: "unauthorized_client", error_description: "Spoofed account." }, res );
						res.end();
					}
				});
			}
			
		}
	} );
	
});

app.post("/oauth2/token", function(req,res) {
	var stateObject = {
		grant_type: req.param("grant_type", null)
		, client_id: req.param("client_id", null)
		, client_secret: req.param("client_secret", null)
		, code: req.param("code", null)
		, redirect_uri: req.param("code", null) };
	var validationStatus = oauth2.validateTokenRequest( stateObject, req.header("Referer") );
	if ( validationStatus.error != null ) {
		oauth2.sendErrorResponse( stateObject, validationStatus, res );
		res.end();
		return;
	}
	
	// if grant_type is authorization_code
	if ( stateObject.grant_type === "authorization_code" ) {
		oauth2.getOAuth2InputByAuthCode( stateObjetc.code, function( authStateObject ) {
			if ( authStateObject == null ) {
				oauth2.sendErrorMessage( sessionData.stateObject, { error: "invalid_request", error_description: "Auth code invalid or expired." }, res );
			} else {
				if ( sessionData.client_id !== authStateObject.client_id ) {
					oauth2.sendErrorMessage( sessionData.stateObject, { error: "invalid_request", error_description: "Auth code client ID not matched." }, res );
				} else {
					if ( sessionData.redirect_uri !== authStateObject.redirect_uri ) {
						oauth2.sendErrorMessage( sessionData.stateObject, { error: "invalid_request", error_description: "Auth code redirect URI not matched." }, res );
					} else {
						oauth2.clientIdLookup( sessionData.client_id, function( app ) {
							if ( app == null ) {
								oauth2.sendErrorMessage( sessionData.stateObject, { error: "invalid_request", error_description: "Client ID is invalid." }, res );
							} else {
								if ( sessionData.client_secret !== app.client_id ) {
									oauth2.sendErrorMessage( sessionData.stateObject, { error: "invalid_request", error_description: "Client secret is invalid." }, res );
								} else {
									
									// check if auth_code isn't expired
									//  -> if expired
									//   -> error
									//  -> if not expired:
									//   -> get session by auth_code
									//    -> if session found:
									//     -> generate authorization_token regardless of one already existing there, set it to expire in XXX and update session
									//     -> remove access_code from the session so it can't be reused
									//     -> send the success response
									//    -> session not found:
									//     -> error
									
								}
							}
						} );
					}
				}
			}
		} );
	} else if ( stateObject.grant_type === "refresh_token" ) {
		
		oauth2.clientIdLookup( sessionData.client_id, function( app ) {
			if ( app == null ) {
				oauth2.sendErrorMessage( sessionData.stateObject, { error: "invalid_client", error_description: "Client ID is invalid." }, res );
			} else {
				if ( sessionData.client_secret !== app.client_id ) {
					oauth2.sendErrorMessage( sessionData.stateObject, { error: "invalid_client", error_description: "Client secret is invalid." }, res );
				} else {
					
					// find user session by refresh token:
					//  -> if found, check if the token exists and check if it expired
					//   -> if that's the case, generate new access token and send it
					//   -> update the session with new token
					// -> otherwise, error, token has to expire first
					// if no session found - error
					
				}
			}
		} );
	}
	
});

app.listen(3000);