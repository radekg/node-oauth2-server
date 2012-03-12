var util = require("util")
	, url = require("url")
	, Db = require('mongodb').Db
	, Connection = require('mongodb').Connection
	, Server = require('mongodb').Server
	, log = require("logging").from(__filename);

function StorageAdapterMongoDB( connection_string ) {
	this.oauth2Server = null;
	this.connection_string = (connection_string != undefined) ? connection_string : null;
};

StorageAdapterMongoDB.prototype.callback_success_default = function( scopes ) {
	log( "connected" );
};
StorageAdapterMongoDB.prototype.callback_fail_default = function( err ) {
	log( "no connection: " + JSON.stringify(err) );
};

StorageAdapterMongoDB.prototype.connect = function( onSuccess, onFault ) {
	
	var __scope = this;
	
	var mongod = {
		requiesAuth: false,
		username: "",
		password: "" };
	var urlParsed = url.parse( this.connection_string );
	var toLog = urlParsed;
	if ( urlParsed.auth ) {
		mongod.requires_auth = true;
		var authParts = urlParsed.auth.split(":");
		mongod.username = authParts[0];
		mongod.password = authParts[1];
		toLog.auth = mongod.username + ":...";
	}
	
	log("Attempting to open a DB connection using: " + url.format( toLog ) + ".");
	
	this.mongodClient = new Db(
		urlParsed.pathname.substr(1, urlParsed.pathname.length )
		, new Server(
			urlParsed.hostname+""
			, parseInt(urlParsed.port)
			, {} ) );
	this.mongodClient.open(function(err, p_client) {
		if ( err ) {
			log("Could not connect to the database.");
			onFault( err );
		} else {
			if ( mongod.requires_auth ) {
				p_client.authenticate( mongod.username, mongod.password, function( err, collection ) {
					if ( err != null ) {
						log("Database authentication failed.");
						onFault( err );
					} else {
						log("Connection with authentication successful. Attempting to load OAuth2 scopes.");
						__scope.load_scopes( __scope, onSuccess, onFault );
					}
				} );
			} else {
				log("Connection successful. Attempting to load OAuth2 scopes.");
				__scope.load_scopes( __scope, onSuccess, onFault );
			}
		}
	});
};

StorageAdapterMongoDB.prototype.load_scopes = function( adapter, onSuccess, onFault ) {
	process.nextTick(function() {
		adapter.mongodClient.collection("scopes", function(err, collection) {
			collection.find({}, function(err, cursor) {
				cursor.toArray( function(err, arr) {
					if ( err ) {
						log("Error while loading scopes.");
						onFault( err );
					} else {
						adapter.oauth2Server.scopes = arr;
						log("Scopes loaded correctly.");
						onSuccess( );
					}
				});
			});
		});
	});
};

StorageAdapterMongoDB.prototype.storeAuthCode = function( code, state, expiry ) {
	if ( !expiry ) {
		expiry = this.oauth2Server.authCodeExpiry;
	}
	log( "Storing authCode " + code + " which will expire in " + expiry + "ms." );
	var expiryDate = new Date( (new Date()).getTime() + expiry );
	this.mongodClient.collection("authCodes", function(err, collection) {
		collection.insert( { auth_code: code, state: state, expires: expiryDate } );
	});
};
StorageAdapterMongoDB.prototype.getOAuth2InputByAuthCode = function( code, callback ) {
	this.mongodClient.collection("authCodes", function(err,collection) {
		collection.findOne( { auth_code: code }, function( err, result ) {
			callback( result == null ? null : result.state );
		} );
	});
};
StorageAdapterMongoDB.prototype.timer_authCodeHandler = function( runAt ) {
	this.mongodClient.collection("authCodes", function(err,collection) {
		collection.remove( { expires: { $lt: runAt } } )
	});
};

StorageAdapterMongoDB.prototype.getOauth2InputBySessionLoginCode = function( code, callback ) {
	var __scope = this;
	this.mongodClient.collection("sessionLoginCodes", function(err, collection) {
		collection.findOne( { code: code }, function(error,result) {
			if ( !result ) {
				callback(null);
			} else {
				process.nextTick( function() {
					__scope.mongodClient.collection("sessionLoginCodes", function( err, n_collection ) {
						result.expires = new Date((new Date()).getTime() + result.expiresBy);
						n_collection.update( { code: result.code }, result );
					});
				} );
				callback(result);
			}
		});
	});
};
StorageAdapterMongoDB.prototype.storeSessionLoginCode = function( code, state, expiry ) {
	if ( !expiry ) {
		expiry = this.oauth2Server.sessionLoginExpiry;
	}
	log( "Storing sessionLoginCode " + code + " which will expire in " + expiry + "ms." );
	var expiryDate = new Date( (new Date()).getTime() + expiry );
	this.mongodClient.collection("sessionLoginCodes", function(err, collection) {
		collection.insert( { code: code, stateObject: state, expires: expiryDate, expiresBy: expiry } );
	});
};
StorageAdapterMongoDB.prototype.removeSessionLoginCode = function( code ) {
	this.mongodClient.collection("sessionLoginCodes", function(err, collection) {
		collection.remove( { code: code } );
	});
};
StorageAdapterMongoDB.prototype.timer_sessionLoginCodeHandler = function( runAt ) {
	this.mongodClient.collection("sessionLoginCodes", function(err,collection) {
		collection.remove( { expires: { $lt: runAt } } )
	});
};

StorageAdapterMongoDB.prototype.updateUserPrivileges = function( user_id, client_id, scopes ) {
	var __scope = this;
	this.getUserAccountBy( { username: user_id }, function( account ) {
		if ( account != null ) {
			if ( account.authorized == null || account.authorized == undefined ) {
				account.authorized = {};
			}
			if ( scopes == null ) {
				delete account.authorized[ client_id ];
			} else {
				account.authorized[ client_id ] = scopes;
			}
			process.nextTick(function() {
				__scope.mongodClient.collection("users", function( err, collection ) {
					collection.update( { username: user_id }, account );
				});
			});
		}
	} );
};
StorageAdapterMongoDB.prototype.assignUserOAuth2Session = function( user_id, auth_code, stateObject ) {
	var __scope = this;
	log("Assigning OAuth2 session. Only one session per user_id/client_id pair.");
	this.getUserOAuth2Session( { user_id: user_id, client_id: stateObject.client_id }, function( oauth2Session ) {
		if ( oauth2Session == null ) {
			log(" : Session doesn't exist for the user. Create new.");
			__scope.mongodClient.collection("oauth2Sessions", function(err, collection) {
				var refreshToken = __scope.oauth2Server.generateRefreshToken( stateObject.client_id );
				collection.insert( { user_id: user_id, auth_code: auth_code, client_id: stateObject.client_id, state: stateObject, refresh_token: refreshToken } );
			});
		} else {
			log(" : Session found, update existing.");
			__scope.mongodClient.collection("oauth2Sessions", function(err, collection) {
				oauth2Session.auth_code = auth_code;
				delete oauth2Session.authorization_token;
				delete authorization_token_created_at;
				delete authorization_token_expire_at;
				__scope.updateUserOAuth2Session( { user_id: user_id, client_id: stateObject.client_id }, oauth2Session );
			});
		}
	} );
};
StorageAdapterMongoDB.prototype.getUserOAuth2Session = function( params, callback ) {
	this.mongodClient.collection("oauth2Sessions", function(err, collection) {
		collection.findOne( params, function( err, result ) {
			callback(result);
		});
	});
};
StorageAdapterMongoDB.prototype.updateUserOAuth2Session = function( params, newSessionObject ) {
	log( "Updating OAuth2 session : ", params, newSessionObject );
	this.mongodClient.collection("oauth2Sessions", function(err, collection) {
		collection.update( params, newSessionObject );
	});
};
StorageAdapterMongoDB.prototype.removeOAuth2UserSession = function( user_id, client_id ) {
	this.mongodClient.collection("oauth2Sessions", function(err, collection) {
		collection.remove( { user_id: user_id, client_id: client_id } );
	});
};

StorageAdapterMongoDB.prototype.getUserAccountBy = function( params, callback ) {
	this.mongodClient.collection("users", function(err, collection) {
		collection.findOne( params, function(err, result) {
			callback(result);
		});
	});
};
StorageAdapterMongoDB.prototype.clientIdLookup = function(client_id, callback) {
	this.mongodClient.collection("apps", function(err, collection) {
		collection.findOne( { client_id: client_id }, function(err, result) {
			callback(result);
		} );
	} );
};
StorageAdapterMongoDB.prototype.clientAppsLookup = function(client_ids, callback) {
	this.mongodClient.collection("apps", function(err, collection) {
		collection.find( { client_id: { $in: client_ids } }, function(err, cursor) {
			cursor.toArray( function(err, arr) {
				callback(arr);
			});
		});
	});
};

exports.StorageAdapterMongoDB = StorageAdapterMongoDB;