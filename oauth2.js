var express = require("express")
	, util = require("util")
	, qs = require("qs")
	, hash = require("jshashes");


function OAuth2Server() {
	var __scope = this;
	this.__$handleClientIdLookup = function(client_id) {
		return true;
	};
	this.__$handleAuthCodeStorage = function(client_id, code) {
		if ( this.__$code_storage == null ) {
			this.__$code_storage = {};
		}
		this.__$code_storage[ code ] = { client_id: client_id, created_at: (new Date()).getTime() };
	};
	this.__$handleAuthCodeTimer = function(scope) {
		if ( __scope.__$code_storage == null ) {
			__scope.__$code_storage = {};
		}
		var runAt = (new Date()).getTime();
		var toDelete = [];
		for ( var key in __scope.__$code_storage ) {
			if ( runAt - __scope.__$code_storage[key].created_at > 60000 ) {
				toDelete.push(key);
			}
		}
		for ( var i=0; i<toDelete.length; i++ ) {
			delete __scope.__$code_storage[ key ];
		}
		
		util.puts("Clear timer " + JSON.stringify( __scope.__$code_storage ) );
	};
	
	this.__$expireAuthCodeTimer = setInterval( __scope.__$handleAuthCodeTimer, 5000 );
};
OAuth2Server.prototype.processAuth = function(response_type, client_id, scope, state) {
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
	
	if ( this.__$handleClientIdLookup( client_id ) ) {
		resp.code = this.generateAuthCode( client_id );
		this.__$handleAuthCodeStorage( client_id, resp.code );
		if ( state != null ) {
			resp.state = state;
		}
		return resp;
	} else {
		resp.error = "unauthorized_client";
		return resp;
	}
	
}
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
}


var oauth2 = new OAuth2Server();
var app = express.createServer();
app.use(express.bodyParser());

app.get("/oauth2/auth", function(req,res) {
	
	var redirect_uri = req.param("redirect_uri", null);
	var response_type = req.param("response_type", null);
	var client_id = req.param("client_id", null);
	var scope = req.param("scope", null);
	var state = req.param("state", null);
	
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
	
});

app.listen(3000);