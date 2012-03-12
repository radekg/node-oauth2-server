var util = require("util")
	, log = require("logging").from(__filename);

function WebAdapterExpress( routes, settings ) {
	
	var $this = this;
	var __$config = settings || {};
	
	this.oauth2Server = null;
	this.routes = routes;
	
	this.setError = function(req, res, message) {
		req.session.oauth2Error = message;
		res.redirect($this.routes.page_error);
	};
	this.page_errorHandler = function(req, res) {
		var error = req.session.oauth2Error;
		log( "Error page : " + error + "." );
		delete req.session.oauth2Error;
		res.render( "error", {
			error: error });
	};
	this.process_logoutHandler = function(req, res) {
		log( "Logging out." );
		req.session.destroy();
		res.redirect($this.routes.page_account);
	};
	this.page_loginHandler = function(req, res) {
		var sessionCode = req.param("ses", null);
		log( "Login page requested." );
		if ( sessionCode == null ) {
			log( " : Not an auth process login." );
			var error = req.session.oauth2Error;
			delete req.session.oauth2Error;
			res.render("login", {
				res: res
				, sessionCode: null
				, error: error });
			return;
		}
		log( "Auth process login requested." );
		$this.oauth2Server.storageAdapter.getOauth2InputBySessionLoginCode( $this.oauth2Server.fixString( sessionCode ), function( sessionData ) {
			if ( sessionData == null ) {
				$this.setError( req, res, "Session expired " + $this.oauth2Server.fixString( sessionCode ) );
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
		log( "Logging in process." );
		$this.oauth2Server.storageAdapter.getUserAccountBy( { username: username, password: password }, function( account ) {
			if ( account != null ) {
				log( " : Account found." );
				req.session.loggedInAccount = account;
				if ( sessionCode != null ) {
					log( " : Session code found, this seeems to be an auth process login." );
					$this.oauth2Server.storageAdapter.getOauth2InputBySessionLoginCode( $this.oauth2Server.fixString( sessionCode ), function( sessionData ) {
						if ( sessionData != null ) {
							log( " : Session data found." );
							if ( account.authorized == null || account.authorized == undefined ) {
								account.authorized = {};
							}
							if ( account.authorized[ sessionData.stateObject.client_id ] == null || account.authorized[ sessionData.stateObject.client_id ] == undefined ) {
								log( " : Application isn't authorized by this user, redirect to scopes page." );
								res.redirect( $this.routes.page_scopes + "?ses=" + $this.oauth2Server.fixString( sessionCode ) );
								res.end();
							} else {
								log( " : Application authorized - generate auth code." );
								var authCode = $this.oauth2Server.generateAuthCode( sessionData.stateObject.client_id );
								$this.oauth2Server.storageAdapter.storeAuthCode( $this.oauth2Server.fixString( authCode ), sessionData.stateObject );
								$this.oauth2Server.sendResponse( sessionData.stateObject, { code: authCode }, res );
							}
						} else {
							log( " : Session data not found, show account page." );
							res.redirect( $this.routes.page_account);
							res.end();
						}
					});
				} else {
					log( " : No session login code, this is an ordinary login." );
					res.redirect( $this.routes.page_account);
					res.end();
				}
			} else {
				log( "Account not found. Invalid login." );
				var _url = $this.routes.page_login;
				if ( sessionCode != null ) {
					_url += "?ses=" + $this.oauth2Server.fixString( sessionCode );
				}
				req.session.oauth2Error = "Could not log you in.";
				res.redirect( _url );
				res.end();
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
		var validationStatus = $this.oauth2Server.validateAuthRequest( stateObject, req.header("Referer") );
		log("Authentication request received.");
		if ( validationStatus.error != null ) {
			log(" : Error validating the input", validationStatus.error, validationStatus.error_description);
			$this.oauth2Server.sendErrorResponse( stateObject, validationStatus, res );
			return;
		}
		log(" : Input is: ", stateObject);
		stateObject.client_id = $this.oauth2Server.fixString( stateObject.client_id );
		
		$this.oauth2Server.storageAdapter.clientIdLookup( stateObject.client_id, function(clientApp) {
			if ( clientApp == null ) {
				log(" : Client app not found.");
				$this.oauth2Server.sendErrorResponse( stateObject, { error: "unauthorized_client", error_description: "Client ID invalid" }, res );
			} else {
				if ( !req.session.loggedInAccount ) {
					log(" : User not logged in, request a login.");
					var loginSessionCode = $this.oauth2Server.generateLoginSessionCode(stateObject.client_id);
					$this.oauth2Server.storageAdapter.storeSessionLoginCode( loginSessionCode, stateObject );
					res.redirect( $this.routes.page_login + "?ses=" + loginSessionCode);
				} else {
					log(" : User logged in.");
					$this.oauth2Server.storageAdapter.getUserAccountBy( { username: req.session.loggedInAccount.username }, function( account ) {
						if ( account != null ) {
							log(" : User account found.");
							if ( account.authorized == null || account.authorized == undefined ) {
								account.authorized = {};
							}
							if ( account.authorized[ stateObject.client_id ] == null || account.authorized[ stateObject.client_id ] == undefined ) {
								log(" : Application isn't approved by user.");
								var loginSessionCode = $this.oauth2Server.generateLoginSessionCode(stateObject.client_id);
								$this.oauth2Server.storageAdapter.storeSessionLoginCode( loginSessionCode, stateObject );
								res.redirect( $this.routes.page_scopes + "?ses=" + loginSessionCode);
							} else {
								log(" : Application already approved by user.");
								var authCode = $this.oauth2Server.generateAuthCode( stateObject.client_id );
								$this.oauth2Server.storageAdapter.storeAuthCode( $this.oauth2Server.fixString( authCode ), stateObject );
								$this.oauth2Server.storageAdapter.assignUserOAuth2Session(
									req.session.loggedInAccount.username
									, $this.oauth2Server.fixString( authCode )
									, stateObject );
								$this.oauth2Server.sendResponse( stateObject, { code: authCode }, res );
							}
						} else {
							log(" : User account not found.");
							$this.oauth2Server.sendErrorResponse( stateObject, { error: "unauthorized_client", error_description: "User account invalid." }, res );
						}
					});
				}
			}
		
		});	
	};
	
	this.page_scopesHandler = function(req,res) {
		log("Scopes approval page requested.");
		if ( !req.session.loggedInAccount ) {
			log(" : User not logged in. Request a login.");
			res.redirect( $this.routes.page_login );
			res.end();
			return;
		}

		var sessionCode = req.param("ses", null);
		if ( sessionCode == null ) {
			log(" : Session code expired.");
			$this.setError( req, res, "Session expired" );
			return;
		}
		
		log(" : Looking for session data.");

		$this.oauth2Server.storageAdapter.getOauth2InputBySessionLoginCode( $this.oauth2Server.fixString( sessionCode ), function( sessionData ) {
			if ( sessionData == null ) {
				log(" : Session data not found. Session is invalid");
				$this.setError( req, res, "Session expired" );
				return;
			} else {
				log(" : Session data found. Loading a client app to find the scopes.");
				$this.oauth2Server.storageAdapter.clientIdLookup( sessionData.stateObject.client_id, function(clientApp) {
					if ( clientApp == null ) {
						log(" : Client app not found. Spooky.");
						$this.setError( req, res, "invalid_request: Client ID invalid" );
					} else {
						log(" : Client app found, load scopes and request approval or denial.");
						var requestedScopes = sessionData.stateObject.scope.split(" ");
						var scopes = [];
						for ( var i=0; i<requestedScopes.length; i++ ) {
							scopes.push( { scope: requestedScopes[i], name: $this.oauth2Server.getScopeName( requestedScopes[i] ) } );
						}
						res.render("scopes", {
							scopes: scopes
							, clientApp: clientApp
							, sessionCode: $this.oauth2Server.fixString( sessionCode ) });
					}
				});
			}
		});	
	};
	
	this.process_scopesHandler = function( req, res ) {
		log("Processing approval.");
		if ( !req.session.loggedInAccount ) {
			log(" : User not logged in. Request a login.");
			res.redirect( $this.routes.page_login );
			res.end();
			return;
		}
		var sessionCode = req.param("ses", null);
		if ( sessionCode == null ) {
			log(" : Session login code expired.");
			$this.setError( req, res, "Session expired" );
			return;
		}
		var accessStatus = req.param("access_status", null);
		if ( accessStatus !== "allow" && accessStatus !== "deny" ) {
			log(" : Acceptance status " + accessStatus + " isn't known.");
			$this.setError( req, res, "Unrecognized acceptance status: " + accessStatus );
			return;
		}
		log(" : Lookup session code.");
		$this.oauth2Server.storageAdapter.getOauth2InputBySessionLoginCode( $this.oauth2Server.fixString( sessionCode ), function( sessionData ) {
			if ( sessionData == null ) {
				log(" : Session data not found.");
				$this.setError( req, res, "Session expired" );
			} else {
				log(" : Session data found.");
				// we don't want people to able to reuse this code:
				process.nextTick(function() {
					$this.oauth2Server.storageAdapter.removeSessionLoginCode( $this.oauth2Server.fixString( sessionCode ) );
				});
				
				// check if user has allowed or denied the access:
				if ( accessStatus == "allow" ) {
					log(" : User allowed.");
					var authCode = $this.oauth2Server.generateAuthCode( sessionData.stateObject.client_id );
					$this.oauth2Server.storageAdapter.storeAuthCode( $this.oauth2Server.fixString( authCode ), sessionData.stateObject );
					$this.oauth2Server.storageAdapter.updateUserPrivileges(
						req.session.loggedInAccount.username
						, sessionData.stateObject.client_id
						, sessionData.stateObject.scope.split(" ") );
					$this.oauth2Server.storageAdapter.assignUserOAuth2Session(
						req.session.loggedInAccount.username
						, $this.oauth2Server.fixString( authCode )
						, sessionData.stateObject );
					$this.oauth2Server.sendResponse( sessionData.stateObject, { code: authCode }, res );
				} else if ( accessStatus == "deny" ) {
					log(" : User denied.");
					$this.oauth2Server.sendErrorResponse( sessionData.stateObject, { error: "access_denied", error_description: "User denied." }, res );
				}
			}
		});	
	};
	
	this.process_deauthorizeAppHandler = function( req,res ) {
		log("Deauth app requested.");
		if ( !req.session.loggedInAccount ) {
			log(" : User not logged in. Request a login.");
			res.redirect( $this.routes.page_account );
			res.end();
			return;
		}
		$this.oauth2Server.storageAdapter.updateUserPrivileges( req.session.loggedInAccount.username, req.param("client_id", null), null);
		log(" : App deauthorized.");
		process.nextTick(function() {
			$this.oauth2Server.storageAdapter.removeOAuth2UserSession( req.session.loggedInAccount.username, req.param("client_id", null) );
			log(" : Sessions for deauthorized app removed.");
		});
		res.redirect( $this.routes.page_account );
	};
	
	this.page_accountHandler = function(req,res) {
		var authorizedApps = [];
		var loggedIn = ( req.session.loggedInAccount != null && req.session.loggedInAccount != undefined );
		if ( loggedIn ) {
			$this.oauth2Server.storageAdapter.getUserAccountBy( { username: req.session.loggedInAccount.username }, function(account) {
				if ( account != null ) {
					var client_ids = [];
					if ( account.authorized != null && account.authorized != undefined ) {
						for ( var key in account.authorized ) {
							client_ids.push( key );
						}
					}
					$this.oauth2Server.storageAdapter.clientAppsLookup( client_ids, function( apps ) {
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
		
		log("Token request : ", stateObject);
		
		var validationStatus = $this.oauth2Server.validateTokenRequest( stateObject, req.header("Referer") );
		if ( validationStatus.error != null ) {
			log(" : Input incorrect : ", validationStatus);
			$this.oauth2Server.sendBodyErrorResponse( validationStatus, res );
			res.end();
			return;
		}

		// if grant_type is authorization_code
		if ( stateObject.grant_type === "authorization_code" ) {
			
			log( " : Authorization code requested." );
			
			$this.oauth2Server.storageAdapter.getOAuth2InputByAuthCode( stateObject.code, function( authStateObject ) {
				if ( authStateObject == null ) {
					log( " : Could not find the input by auth code - expired?" );
					$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Auth code invalid or expired." }, res );
				} else {
					if ( stateObject.client_id !== authStateObject.client_id ) {
						log( " : client ID not matched" );
						$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Auth code client ID not matched." }, res );
					} else {
						//if ( stateObject.redirect_uri !== authStateObject.redirect_uri ) {
						//	$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Auth code redirect URI not matched." }, res );
						//} else {
							$this.oauth2Server.storageAdapter.clientIdLookup( stateObject.client_id, function( app ) {
								if ( app == null ) {
									log( " : Client app not found. Spooky." );
									$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Client ID is invalid." }, res );
								} else {
									if ( stateObject.client_secret !== app.client_secret ) {
										log( " : App found but client secret invalid." );
										$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Client secret is invalid." }, res );
									} else {
										$this.oauth2Server.storageAdapter.getUserOAuth2Session( { auth_code: stateObject.code }, function( oauth2Session ) {
											if ( oauth2Session == null ) {
												log( " : OAUth2 session not found, incorrect auth code." );
												$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Auth code invalid or expired." }, res );
											} else {
												log( " : Auth code correct. Data validated, issuing the token." );
												delete oauth2Session.auth_code;
												oauth2Session.authorization_token = $this.oauth2Server.generateAuthToken( oauth2Session.client_id );
												oauth2Session.authorization_token_created_at = new Date();
												oauth2Session.authorization_token_expire_at = new Date( oauth2Session.authorization_token_created_at.getTime() + 3600 * 1000 );
												$this.oauth2Server.storageAdapter.updateUserOAuth2Session( { auth_code: stateObject.code }, oauth2Session );

												$this.oauth2Server.sendBodyResponse( {
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
			
			log( " : Refresh token requested." );
			
			$this.oauth2Server.storageAdapter.clientIdLookup( stateObject.client_id, function( app ) {
				if ( app == null ) {
					log( " : Client app not found" );
					$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Client ID is invalid." }, res );
				} else {
					if ( stateObject.client_secret !== app.client_secret ) {
						log( " : Client secret is invalid." );
						$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Client secret is invalid." }, res );
					} else {
						$this.oauth2Server.storageAdapter.getUserOAuth2Session( { refresh_token: stateObject.refresh_token }, function( oauth2Session ) {
							if ( oauth2Session == null ) {
								log( " : Could not find a session by refresh token. Either the app is deauthorized or refresh token invalid." );
								$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Unrecognized refresh token." }, res );
							} else {
								if ( oauth2Session.authorization_token == null || oauth2Session.authorization_token == undefined ) {
									log( " : There's no auth token on this session. Session is invalid." );
									$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Invalid session." }, res );
								} else {
									if ( oauth2Session.authorization_token_expire_at.getTime() > (new Date()).getTime() ) {
										log( " : Authorization_token has not expired yet." );
										$this.oauth2Server.sendBodyErrorResponse( { error: "invalid_request", error_description: "Refresh token requested too early." }, res );
									} else {
										log( " : Generating new auth token." );
										oauth2Session.authorization_token = $this.oauth2Server.generateAuthToken( oauth2Session.client_id );
										oauth2Session.authorization_token_created_at = new Date();
										oauth2Session.authorization_token_expire_at = new Date( oauth2Session.authorization_token_created_at.getTime() + 3600 * 1000 );

										$this.oauth2Server.storageAdapter.updateUserOAuth2Session( { refresh_token: stateObject.refresh_token }, oauth2Session );

										$this.oauth2Server.sendBodyResponse( {
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
