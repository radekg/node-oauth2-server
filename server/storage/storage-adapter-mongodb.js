var util = require("util")
	, url = require("url")
	, Db = require('mongodb').Db
	, Connection = require('mongodb').Connection
	, Server = require('mongodb').Server;

function StorageAdapterMongoDB( connection_string ) {
	this.oauth2Server = null;
	this.connection_string = (connection_string != undefined) ? connection_string : null;
};

StorageAdapterMongoDB.prototype.callback_success_default = function( scopes ) {
	util.puts( "connected" );
};
StorageAdapterMongoDB.prototype.callback_fail_default = function( err ) {
	util.puts( "no connection: " + JSON.stringify(err) );
};

StorageAdapterMongoDB.prototype.connect = function( onSuccess, onFault ) {
	
	util.puts("Attempting to open a DB connection using: " + this.connection_string + ".");
	
	var __scope = this;
	
	var mongod = {
		requiesAuth: false,
		username: "",
		password: "" };
	var urlParsed = url.parse( this.connection_string );
	if ( urlParsed.auth ) {
		mongod.requires_auth = true;
		var authParts = urlParsed.auth.split(":");
		mongod.username = authParts[0];
		mongod.password = authParts[1];
	}
	
	this.mongodClient = new Db(
		urlParsed.pathname.substr(1, urlParsed.pathname.length )
		, new Server(
			urlParsed.hostname+""
			, parseInt(urlParsed.port)
			, {} ) );
	this.mongodClient.open(function(err, p_client) {
		if ( err ) {
			util.puts("Could not connect to the database.");
			onFault( err );
		} else {
			if ( mongod.requires_auth ) {
				p_client.authenticate( mongod.username, mongod.password, function( err, collection ) {
					if ( err != null ) {
						util.puts("Database authentication failed.");
						onFault( err );
					} else {
						util.puts("Connection with authentication successful. Attempting to load OAuth2 scopes.");
						__scope.load_scopes( __scope, onSuccess, onFault );
					}
				} );
			} else {
				util.puts("Connection successful. Attempting to load OAuth2 scopes.");
				__scope.load_scopes( __scope, onSuccess, onFault );
			}
		}
	});
};

StorageAdapterMongoDB.prototype.load_scopes = function( adapter, onSuccess, onFault ) {
	adapter.mongodClient.collection("scopes", function(err, collection) {
		collection.find({}, function(err, cursor) {
			cursor.toArray( function(err, arr) {
				if ( err ) {
					util.puts("Error while loading scopes.");
					onFault( err );
				} else {
					adapter.oauth2Server.scopes = arr;
					util.puts("Scopes loaded correctly.");
					onSuccess( );
				}
			});
		});
	});
};

StorageAdapterMongoDB.prototype.storeAuthCode = function( code, state, expiry ) {
	if ( !expiry ) {
		expiry = 60000;
	}
	var expiryDate = new Date( (new Date()).getTime() + expiry );
	this.mongodClient.collection("authCodes", function(err, collection) {
		collection.insert( { auth_code: code, state: state, expires: expiryDate.getTime() } );
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
	// util.puts("Running an auth code clean handler");
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
						result.expires = ((new Date()).getTime() + result.expiresBy);
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
		expiry = 60000;
	}
	var expiryDate = new Date( (new Date()).getTime() + expiry );
	this.mongodClient.collection("sessionLoginCodes", function(err, collection) {
		collection.insert( { code: code, stateObject: state, expires: expiryDate.getTime(), expiresBy: expiry } );
	});
};
StorageAdapterMongoDB.prototype.timer_sessionLoginCodeHandler = function( runAt ) {
	// util.puts("Running a session login code clean handler");
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
	this.getUserOAuth2Session( { user_id: user_id, client_id: stateObject.client_id }, function( oauth2Session ) {
		if ( oauth2Session == null ) {
			__scope.mongodClient.collection("oauth2Sessions", function(err, collection) {
				var refreshToken = __scope.oauth2Server.generateRefreshToken( stateObject.client_id );
				collection.insert( { user_id: user_id, auth_code: auth_code, client_id: stateObject.client_id, state: stateObject, refresh_token: refreshToken } );
			});
		} else {
			__scope.mongodClient.collection("oauth2Sessions", function(err, collection) {
				oauth2Session.auth_code = auth_code;
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
	this.mongodClient.collection("oauth2Sessions", function(err, collection) {
		collection.update( params, newSessionObject );
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