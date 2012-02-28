var util = require("util")
	, hash = require("jshashes");

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
