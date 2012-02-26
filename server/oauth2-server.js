var util = require("util")
	, hash = require("jshashes");

function OAuth2Server( settings ) {
	
	var config = settings || {};
	var __scope = this;
	
	this.scopes = config.scopes || [];
	this.authCodeTimeout = config.authCodeTimeout || 60000;
	this.loginSessionCodeTimeout = config.loginSessionCodeTimeout || 60000;
	this.requireAllScopes = true;
	
	this.__$handleAuthCodeTimer = function(scope) {
		if ( __scope.__$code_storage == null ) {
			__scope.__$code_storage = {};
		}
		var runAt = (new Date()).getTime();
		var toDelete = [];
		for ( var key in __scope.__$code_storage ) {
			if ( runAt - __scope.__$code_storage[key].created_at > __scope.authCodeTimeout ) {
				toDelete.push(key);
			}
		}
		for ( var i=0; i<toDelete.length; i++ ) {
			delete __scope.__$code_storage[ key ];
		}
	};
	this.__$handleSessionLoginCodeTimer = function(scope) {
		if ( __scope.__$session_code_storage == null ) {
			__scope.__$session_code_storage = {};
		}
		var runAt = (new Date()).getTime();
		var toDelete = [];
		for ( var key in __scope.__$session_code_storage ) {
			if ( runAt - __scope.__$session_code_storage[key].created_at > __scope.loginSessionCodeTimeout ) {
				toDelete.push(key);
			}
		}
		for ( var i=0; i<toDelete.length; i++ ) {
			delete __scope.__$session_code_storage[ key ];
		}
	};
	
	this.__$expireAuthCodeTimer = setInterval( __scope.__$handleAuthCodeTimer, 5000 );
	this.__$expireSessionLoginCodeTimer = setInterval( __scope.__$handleSessionLoginCodeTimer, 5000 );
};

// TO OVERRIDE
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

OAuth2Server.prototype.doAuthCodeStorage = function(client_id, code) {
	if ( this.__$code_storage == null ) {
		this.__$code_storage = {};
	}
	this.__$code_storage[ code ] = { client_id: client_id, created_at: (new Date()).getTime() };
};

OAuth2Server.prototype.doLoginSessionCodeStorage = function( client_id, code, redirect_uri, response_type, scope, state ) {
	if ( this.__$session_code_storage == null ) {
		this.__$session_code_storage = {};
	}
	this.__$session_code_storage[ code ] = {
		client_id: client_id
		, redirect_uri: redirect_uri
		, response_type: response_type
		, scope: scope
		, state: state
		, created_at: (new Date()).getTime() };
};

OAuth2Server.prototype.isLoginSessionCodeValid = function( code ) {
	if ( this.__$session_code_storage == null ) {
		this.__$session_code_storage = {};
	}
	if ( this.__$session_code_storage[ code ] != null ) {
		this.__$session_code_storage[ code ].created_at = (new Date()).getTime();
		return true;
	}
	return false;
};

OAuth2Server.prototype.getOauth2InputBySessionLoginCode = function( code ) {
	if ( this.__$session_code_storage[ code ] != null ) {
		this.__$session_code_storage[ code ].created_at = (new Date()).getTime();
		var r = {};
		for ( var key in this.__$session_code_storage[ code ] ) {
			r[ key ] = this.__$session_code_storage[ code ][key];
		}
		return r;
	}
	return null;
};

OAuth2Server.prototype.processLookup = function(response_type, client_id, scope, state) {
	var resp = {};
	if ( response_type == null ) {
		resp.error = "invalid_request";
		resp.error_description = "Parameter response_type not given.";
		if ( state != null ) {
			resp.state = state;
		}
		return resp;
	}
	
	if ( client_id == null ) {
		resp.error = "invalid_request";
		resp.error_description = "Parameter client_id not given.";
		if ( state != null ) {
			resp.state = state;
		}
		return resp;
	}
	
	if ( response_type !== "code" ) {
		resp.error = "invalid_request";
		resp.error_description = "Parameter response_type has a wrong value.";
		if ( state != null ) {
			resp.state = state;
		}
		return resp;
	}
	
	if ( this.clientIdExistsLookup( client_id ) != null ) {
		
		resp.scope = scope;
		resp.state = state;
		// 
		/*
		resp.code = this.generateAuthCode( client_id );
		this.doAuthCodeStorage( client_id, resp.code );
		if ( state != null ) {
			resp.state = state;
		}
		return resp;
		*/
		
		
	} else {
		resp.error = "unauthorized_client";
		return resp;
	}
	
}
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
