var util = require("util");

function WebAdapterExpress( routes, settings ) {
	
	var __$scope = this;
	var __$config = settings || {
		
	};
	
	this.oauth2Server = null;
	this.routes = routes;
	
	this.setError = function(req, res, message) {
		req.session.oauth2Error = message;
		res.redirect(__$scope.routes.page_error);
	};
	this.page_errorHandler = function(req, res) {
		var error = req.session.oauth2Error;
		delete req.session.oauth2Error;
		res.render( "error", {
			error: error });
	};
	this.process_logoutHandler = function(req, res) {
		req.session.destroy();
		res.redirect(__$scope.routes.page_account);
	};
	this.page_loginHandler = function(req, res) {
		var sessionCode = req.param("ses", null);
		if ( sessionCode == null ) {
			__$scope.setError( req, res, "Session expired" );
			return;
		}
		__$scope.oauth2Server.storageAdapter.getOauth2InputBySessionLoginCode( __$scope.oauth2Server.fixString( sessionCode ), function( sessionData ) {
			if ( sessionData == null ) {
				__$scope.setError( req, res, "Session expired " + __$scope.oauth2Server.fixString( sessionCode ) );
			} else {
				var error = req.session.oauth2Error;
				delete req.session.oauth2Error;
				res.render("login", {
					res: res
					, sessionCode: sessionCode
					, error: error });
			}
		});
	};
	this.process_loginHandler = function( req,res ) {
		var sessionCode = req.param("ses", null);
		var username = req.param("username", null);
		var password = req.param("password", null);
		if ( sessionCode == null ) {
			__$scope.setError( req, res, "Session expired" );
			return;
		}
		__$scope.oauth2Server.storageAdapter.getOauth2InputBySessionLoginCode( __$scope.oauth2Server.fixString( sessionCode ), function( sessionData ) {
			if ( sessionData == null ) {
				__$scope.setError( req, res, "Session expired " + __$scope.oauth2Server.fixString( sessionCode ) );
			} else {
				__$scope.oauth2Server.storageAdapter.getUserAccountBy( { username: username, password: password }, function( account ) {
					if ( account != null ) {
						
						req.session.loggedInAccount = account;
						
						if ( account.authorized == null || account.authorized == undefined ) {
							account.authorized = {};
						}
						if ( account.authorized[ sessionData.stateObject.client_id ] == null || account.authorized[ sessionData.stateObject.client_id ] == undefined ) {
							res.redirect( __$scope.routes.page_scopes + "?ses=" + __$scope.oauth2Server.fixString( sessionCode ) );
							res.end();
						} else {
							var authCode = __$scope.oauth2Server.generateAuthCode( sessionData.stateObject.client_id );
							__$scope.oauth2Server.storageAdapter.storeAuthCode( __$scope.oauth2Server.fixString( authCode ), sessionData.stateObject );
							__$scope.oauth2Server.sendResponse( sessionData.stateObject, { code: authCode }, res );
						}
						
					} else {
						req.session.oauth2Error = "Could not log you in.";
						res.redirect( __$scope.routes.page_login + "?ses=" + __$scope.oauth2Server.fixString( sessionCode ));
						res.end();
					}
				} );
			}
		});	
	};
	
	this.process_authHandler = function( req, res ) {
		var stateObject = {
			client_id: req.param("client_id", null)
			, redirect_uri: req.param("redirect_uri", null)
			, response_type: req.param("response_type", null)
			, scope: req.param("scope", null)
			, state: req.param("state", null) };
		var validationStatus = __$scope.oauth2Server.validateAuthRequest( stateObject, req.header("Referer") );
		if ( validationStatus.error != null ) {
			__$scope.oauth2Server.sendErrorResponse( stateObject, validationStatus, res );
			return;
		}

		stateObject.client_id = __$scope.oauth2Server.fixString( stateObject.client_id );
		
		__$scope.oauth2Server.storageAdapter.clientIdLookup( stateObject.client_id, function(clientApp) {
			
			if ( clientApp == null ) {
				__$scope.oauth2Server.sendErrorResponse( stateObject, { error: "unauthorized_client", error_description: "Client ID invalid" }, res );
			} else {
				if ( !req.session.loggedInAccount ) {
					var loginSessionCode = __$scope.oauth2Server.generateLoginSessionCode(stateObject.client_id);
					__$scope.oauth2Server.storageAdapter.storeSessionLoginCode( loginSessionCode, stateObject );
					res.redirect( __$scope.routes.page_login + "?ses=" + loginSessionCode);
				} else {
					__$scope.oauth2Server.storageAdapter.getUserAccountBy( { username: req.session.loggedInAccount.username }, function( account ) {
						if ( account != null ) {
							if ( account.authorized == null || account.authorized == undefined ) {
								account.authorized = {};
							}
							if ( account.authorized[ stateObject.client_id ] == null || account.authorized[ stateObject.client_id ] == undefined ) {
								var loginSessionCode = __$scope.oauth2Server.generateLoginSessionCode(stateObject.client_id);
								__$scope.oauth2Server.storageAdapter.storeSessionLoginCode( loginSessionCode, stateObject );
								res.redirect( __$scope.routes.page_scopes + "?ses=" + loginSessionCode);
							} else {
								var authCode = __$scope.oauth2Server.generateAuthCode( stateObject.client_id );
								__$scope.oauth2Server.storageAdapter.storeAuthCode( __$scope.oauth2Server.fixString( authCode ), stateObject );
								__$scope.oauth2Server.storageAdapter.assignUserOAuth2Session(
									req.session.loggedInAccount.username
									, __$scope.oauth2Server.fixString( authCode )
									, stateObject );
								__$scope.oauth2Server.sendResponse( stateObject, { code: authCode }, res );
							}
						} else {
							__$scope.oauth2Server.sendErrorResponse( stateObject, { error: "unauthorized_client", error_description: "Spoofed account." }, res );
						}
					});
				}
			}
		
		});	
	};
	
	this.page_scopesHandler = function(req,res) {
		if ( !req.session.loggedInAccount ) {
			res.redirect( __$scope.routes.page_login );
			res.end();
			return;
		}

		var sessionCode = req.param("ses", null);
		if ( sessionCode == null ) {
			__$scope.setError( req, res, "Session expired" );
			return;
		}

		__$scope.oauth2Server.storageAdapter.getOauth2InputBySessionLoginCode( __$scope.oauth2Server.fixString( sessionCode ), function( sessionData ) {
			if ( sessionData == null ) {
				__$scope.setError( req, res, "Session expired" );
				return;
			} else {
				__$scope.oauth2Server.storageAdapter.clientIdLookup( sessionData.stateObject.client_id, function(clientApp) {
					if ( clientApp == null ) {
						__$scope.setError( req, res, "invalid_request: Client ID invalid" );
					} else {
						var requestedScopes = sessionData.stateObject.scope.split(" ");
						var scopes = [];
						for ( var i=0; i<requestedScopes.length; i++ ) {
							scopes.push( { scope: requestedScopes[i], name: __$scope.oauth2Server.getScopeName( requestedScopes[i] ) } );
						}
						res.render("scopes", {
							scopes: scopes
							, clientApp: clientApp
							, sessionCode: __$scope.oauth2Server.fixString( sessionCode ) });
					}
				});
			}
		});	
	};
	
	this.process_scopesHandler = function( req, res ) {
		if ( !req.session.loggedInAccount ) {
			res.redirect( __$scope.routes.page_login );
			res.end();
			return;
		}
		var sessionCode = req.param("ses", null);
		if ( sessionCode == null ) {
			__$scope.setError( req, res, "Session expired" );
			return;
		}
		var accessStatus = req.param("access_status", null);
		if ( accessStatus !== "allow" && accessStatus !== "deny" ) {
			__$scope.setError( req, res, "Unrecognized acceptance status: " + accessStatus );
			return;
		}
		__$scope.oauth2Server.storageAdapter.getOauth2InputBySessionLoginCode( __$scope.oauth2Server.fixString( sessionCode ), function( sessionData ) {
			if ( sessionData == null ) {
				__$scope.setError( req, res, "Session expired" );
			} else {
				// check if user has allowed or denied the access:
				if ( accessStatus == "allow" ) {
					var authCode = __$scope.oauth2Server.generateAuthCode( sessionData.stateObject.client_id );
					__$scope.oauth2Server.storageAdapter.storeAuthCode( __$scope.oauth2Server.fixString( authCode ), sessionData.stateObject );
					__$scope.oauth2Server.storageAdapter.updateUserPrivileges(
						req.session.loggedInAccount.username
						, sessionData.stateObject.client_id
						, sessionData.stateObject.scope.split(" ") );
					__$scope.oauth2Server.storageAdapter.assignUserOAuth2Session(
						req.session.loggedInAccount.username
						, __$scope.oauth2Server.fixString( authCode )
						, sessionData.stateObject );
					__$scope.oauth2Server.sendResponse( sessionData.stateObject, { code: authCode }, res );
				} else if ( accessStatus == "deny" ) {
					__$scope.oauth2Server.sendErrorResponse( sessionData.stateObject, { error: "access_denied", error_description: "User denied." }, res );
				}
			}
		});	
	};
	
	this.process_deauthorizeAppHandler = function( req,res ) {
		if ( !req.session.loggedInAccount ) {
			res.redirect( __$scope.routes.page_login );
			res.end();
			return;
		}
		__$scope.oauth2Server.storageAdapter.updateUserPrivileges( req.session.loggedInAccount.username, req.param("client_id", null), null);
		res.redirect( __$scope.routes.page_account );
	};
	
	this.page_accountHandler = function(req,res) {
		var authorizedApps = [];
		var loggedIn = ( req.session.loggedInAccount != null && req.session.loggedInAccount != undefined );
		if ( loggedIn ) {
			__$scope.oauth2Server.storageAdapter.getUserAccountBy( { username: req.session.loggedInAccount.username }, function(account) {
				if ( account != null ) {
					var client_ids = [];
					if ( account.authorized != null && account.authorized != undefined ) {
						for ( var key in account.authorized ) {
							client_ids.push( key );
						}
					}
					__$scope.oauth2Server.storageAdapter.clientAppsLookup( client_ids, function( apps ) {
						res.render("account", {
							loggedIn: loggedIn
							, authorizedApps: apps
							, error: null
						});
					});
				} else {
					res.render("account", {
						loggedIn: loggedIn
						, authorizedApps: []
						, error: "no_account"
					});
				}
			});
		} else {
			res.render("account", {
				loggedIn: loggedIn
				, authorizedApps: []
				, error: null
			});
		}
	};
	
	this.process_tokenHandler = function( req, res ) {
		var stateObject = {
			grant_type: req.param("grant_type", null)
			, client_id: req.param("client_id", null)
			, client_secret: req.param("client_secret", null)
			, code: req.param("code", null)
			//, redirect_uri: req.param("code", null)
			, refresh_token: req.param("refresh_token", null) };
		var validationStatus = __$scope.oauth2Server.validateTokenRequest( stateObject, req.header("Referer") );
		if ( validationStatus.error != null ) {
			__$scope.oauth2Server.sendBodyErrorResponse( validationStatus, res );
			res.end();
			return;
		}

		// if grant_type is authorization_code
		if ( stateObject.grant_type === "authorization_code" ) {
			
			util.puts( "auth code" );
			
			__$scope.oauth2Server.storageAdapter.getOAuth2InputByAuthCode( stateObject.code, function( authStateObject ) {
				
				util.puts( "auth state object" );
				
				if ( authStateObject == null ) {
					__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Auth code invalid or expired (1)." }, res );
				} else {
					if ( stateObject.client_id !== authStateObject.client_id ) {
						__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Auth code client ID not matched." }, res );
					} else {
						//if ( stateObject.redirect_uri !== authStateObject.redirect_uri ) {
						//	__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Auth code redirect URI not matched." }, res );
						//} else {
							__$scope.oauth2Server.storageAdapter.clientIdLookup( stateObject.client_id, function( app ) {
								if ( app == null ) {
									__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Client ID is invalid." }, res );
								} else {
									if ( stateObject.client_secret !== app.client_secret ) {
										__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Client secret is invalid." }, res );
									} else {

										__$scope.oauth2Server.storageAdapter.getUserOAuth2Session( { auth_code: stateObject.code }, function( oauth2Session ) {
											if ( oauth2Session == null ) {
												__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Auth code invalid or expired (2)." }, res );
											} else {
												
												util.puts( "issuing the token" );
												
												delete oauth2Session.auth_code;
												oauth2Session.authorization_token = __$scope.oauth2Server.generateAuthToken( oauth2Session.client_id );
												oauth2Session.authorization_token_created_at = new Date();
												oauth2Session.authorization_token_expire_at = new Date( oauth2Session.authorization_token_created_at.getTime() + 3600 * 1000 );
												__$scope.oauth2Server.storageAdapter.updateUserOAuth2Session( { auth_code: stateObject.code }, oauth2Session );

												__$scope.oauth2Server.sendBodyResponse( {
													authorization_token: oauth2Session.authorization_token
													, refresh_token: oauth2Session.refresh_token
													, expires_in: 3600
												}, res );

											}
										} );

									}
								}
							} );
						//}
					}
				}
			} );
		} else if ( stateObject.grant_type === "refresh_token" ) {
			
			util.puts( "Requested a refresh token" );
			
			__$scope.oauth2Server.storageAdapter.clientIdLookup( stateObject.client_id, function( app ) {
				if ( app == null ) {
					util.puts( "client app not found" );
					__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Client ID is invalid." }, res );
				} else {
					util.puts( "client app found" );
					if ( stateObject.client_secret !== app.client_secret ) {
						util.puts( "client secret can't be matched" );
						__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Client secret is invalid." }, res );
					} else {
						util.puts( "client secret is OK, looking for the session using a refresh token" );
						__$scope.oauth2Server.storageAdapter.getUserOAuth2Session( { refresh_token: stateObject.refresh_token }, function( oauth2Session ) {
							if ( oauth2Session == null ) {
								util.puts( "session not found - refresh token is invalid?" );
								__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Unrecognized refresh token." }, res );
							} else {
								util.puts( "session is OK, refresh token seems to be OK" );
								if ( oauth2Session.authorization_token == null || oauth2Session.authorization_token == undefined ) {
									util.puts( "but there's no authorization_token on the session, session could be somehow spoofed or broken" );
									__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Invalid session." }, res );
								} else {
									if ( oauth2Session.authorization_token_expire_at.getTime() > (new Date()).getTime() ) {
										util.puts( "authorization_token has not expired yet" );
										__$scope.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Refresh token requested too early." }, res );
									} else {
										util.puts( "generating a new authorization_token" );
										oauth2Session.authorization_token = __$scope.oauth2Server.generateAuthToken( oauth2Session.client_id );
										oauth2Session.authorization_token_created_at = new Date();
										oauth2Session.authorization_token_expire_at = new Date( oauth2Session.authorization_token_created_at.getTime() + 3600 * 1000 );

										__$scope.oauth2Server.storageAdapter.updateUserOAuth2Session( { refresh_token: stateObject.refresh_token }, oauth2Session );

										__$scope.oauth2Server.sendBodyResponse( {
											authorization_token: oauth2Session.authorization_token
											, expires_in: 3600
										}, res );

									}
								}
							}
						} );

					}
				}
			} );
		}	
	};
	
};

exports.WebAdapterExpress = WebAdapterExpress;
