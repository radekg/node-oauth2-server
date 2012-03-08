var util = require("util")
	, hash = require("jshashes")
	, url = require("url");

function OAuth2Server( settings ) {
	
	var config = settings || {};
	var __scope = this;
	
	this.scopes = config.scopes || [];
	this.expiryDefault = config.expiryDefault || 60000;
	this.sessionLoginExpiryDefault = config.sessionLoginExpiryDefault || 60000;
	
	this.__$handleAuthCodeTimer = function(scope) {
		if ( __scope.timer_authCodeHandler ) {
			__scope.timer_authCodeHandler( (new Date()).getTime() );
		}
	};
	this.__$handleSessionLoginCodeTimer = function(scope) {
		if ( __scope.timer_sessionLoginCodeHandler ) {
			__scope.timer_sessionLoginCodeHandler( (new Date()).getTime() );
		}
	};
	
	this.__$expireAuthCodeTimer = setInterval( __scope.__$handleAuthCodeTimer, 5000 );
	this.__$expireSessionLoginCodeTimer = setInterval( __scope.__$handleSessionLoginCodeTimer, 5000 );
};

// TO OVERRIDE
OAuth2Server.prototype.timer_authCodeHandler = null;
OAuth2Server.prototype.timer_sessionLoginCodeHandler = null;
OAuth2Server.prototype.storeAuthCode = function( client_id ) {};
OAuth2Server.prototype.storeSessionLoginCode = function( client_id ) {};
OAuth2Server.prototype.getOauth2InputBySessionLoginCode = function(code, callback) {};
OAuth2Server.prototype.accountLogin = function( client_id ) { return null };
OAuth2Server.prototype.accountAllowedScopes = function( client_id ) { return null };
OAuth2Server.prototype.clientIdExistsLookup = function( client_id ) { return null };

// INTERNALS:

OAuth2Server.prototype.getScopeName = function(scope) {
	for ( var i=0; i<this.scopes.length; i++ ) {
		if ( this.scopes[i].key == scope ) {
			return this.scopes[i].name;
		}
	}
	return null;
};

OAuth2Server.prototype.sendResponse = function( stateObject, data, response ) {
	if ( stateObject.redirect_uri != null ) {
		var _url = stateObject.redirect_uri + "?";
		for ( var key in data ) {
			_url += key + "=" + dataObject[key] + "&";
		}
		if ( stateObject.state != null ) {
			_url += "state=" + stateObject.state;
		}
		if ( _url[ _url.length -1 ] == "&" ) {
			_url = _url.substr( 0, _url.length - 1 );
		}
		response.redirect(_url);
	} else {
		response.writeHead(200, JSON.stringify( data ));
	}
}

OAuth2Server.prototype.sendErrorResponse = function( stateObject, errorObject, response ) {
	if ( stateObject.redirect_uri != null ) {
		var _url = stateObject.redirect_uri + "?";
		for ( var key in errorObject ) {
			_url += key + "=" + errorObject[key] + "&";
		}
		if ( stateObject.state != null ) {
			_url += "state=" + stateObject.state;
		}
		if ( _url[ _url.length -1 ] == "&" ) {
			_url = _url.substr( 0, _url.length - 1 );
		}
		response.redirect(_url);
	} else {
		response.writeHead(400, errorObject.error + ": " + errorObject.error_description);
	}
}

OAuth2Server.prototype.validateAuthRequest = function(stateObject, referer) {
	var resp = {};
	if ( stateObject.response_type == null ) {
		resp.error = "invalid_request";
		resp.error_description = "Parameter response_type required.";
		return resp;
	}
	if ( stateObject.response_type !== "code" ) {
		resp.error = "invalid_request";
		resp.error_description = "Parameter response_type must be 'code'. Other values currently unsupported.";
		return resp;
	}
	if ( stateObject.client_id == null ) {
		resp.error = "invalid_request";
		resp.error_description = "Parameter client_id required.";
		return resp;
	}
	if ( stateObject.redirect_uri != null ) {
		var parsedUri = url.parse( stateObject.redirect_uri );
		var parsedReferer = null;
		if ( typeof(referer) == "string" ) {
			parsedReferer = url.parse( referer )
		}
		if ( parsedReferer && parsedReferer.hostname ) {
			if ( parsedUri.hostname !== parsedReferer.hostname ) {
				resp.error = "invalid_request";
				resp.error_description = "Can't redirect to unauthorized URI.";
				return resp;
			}
		} else {
			resp.error = "invalid_request";
			resp.error_description = "Can't verify the origin of this request.";
			return resp;
		}
	} else {
		// lookup app details to see if the uri stored on the app settings
		// and compare those...
	}
	
	var requestedScopes = stateObject.scope.split(" ");
	var scopes = [];
	for ( var i=0; i<requestedScopes.length; i++ ) {
		var aScopeName = this.getScopeName( requestedScopes[i] );
		if ( aScopeName == null ) {
			resp.error = "invalid_scope";
			resp.error_description = requestedScopes[i];
			return resp ;
		}
	}
	
	return resp;
}


OAuth2Server.prototype.validateTokenRequest = function(stateObject) {
	var resp = {};
	if ( stateObject.grant_type == null ) {
		resp.error = "invalid_request";
		resp.error_description = "Grant type not specified.";
		return resp;
	}
	if ( stateObject.grant_type !== "authorization_code" && stateObject.grant_type !== "refresh_token" ) {
		resp.error = "unsupported_grant_type";
		resp.error_description = "Parameter grant_type must be 'authorization_code' or 'refresh_token'. Other values currently unsupported.";
		return resp;
	}
	if ( stateObject.grant_type === "authorization_code" ) {
		if ( stateObject.code == null ) {
			resp.error = "invalid_request";
			resp.error_description = "Parameter code required.";
			return resp;
		}
		if ( stateObject.redirect_uri == null ) {
			resp.error = "invalid_request";
			resp.error_description = "Parameter redirect_uri required.";
			return resp;
		}
	}
	if ( stateObject.client_id == null ) {
		resp.error = "invalid_request";
		resp.error_description = "Parameter client_id required.";
		return resp;
	}
	if ( stateObject.client_secret == null ) {
		resp.error = "invalid_request";
		resp.error_description = "Parameter client_secret required.";
		return resp;
	}
	
	return resp;
}

OAuth2Server.prototype.generateRefreshToken = function( client_id ) {
	return this.generateLoginSessionCode();
};
OAuth2Server.prototype.generateAuthToken = function( client_id ) {
	return this.generateLoginSessionCode();
};
OAuth2Server.prototype.generateLoginSessionCode = function( client_id ) {
	var code = new hash.SHA1().b64( (new Date()).toString() + Math.random() + client_id + this.randomString(50) );
	return code;
};
OAuth2Server.prototype.generateAuthCode = function( client_id ) {
	var code = new hash.SHA1().b64( (new Date()).toString() + Math.random() + client_id + this.randomString(8) );
	return code;
};
OAuth2Server.prototype.randomString = function(length) {
	var chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";
	var randomstring = '';
	for (var i=0; i<length; i++) {
		var rnum = Math.floor(Math.random() * chars.length);
		randomstring += chars.substring(rnum,rnum+1);
	}
	return randomstring;
};
OAuth2Server.prototype.fixString = function(str) {
	str = str.replace(/\s/,"+");
	return str;
};

exports.OAuth2Server = OAuth2Server;
