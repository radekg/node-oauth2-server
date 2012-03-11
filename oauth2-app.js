var express = require("express")
	, util = require("util")
	, qs = require("qs")
	, url = require("url")
	, OAuth2Server = require("./server/oauth2-server").OAuth2Server
	, StorageAdapter = require("./server/storage/storage-adapter-mongodb").StorageAdapterMongoDB
	, WebAdapter = require("./server/web/web-adapter-express").WebAdapterExpress
	, MongoStore = require('connect-mongo');

var app = express.createServer();
app.set('view options', { layout: false });
app.set('view engine', 'jade');
app.use(express.static(__dirname + '/public'));
app.use(express.cookieParser());
app.use(express.session({
	secret: "keyboard cat"
	, store: new MongoStore({
	    db: 'oauth2-server-test',
	    host: '127.0.0.1',
	    collection: 'userSessions' }) } ) );
app.use(express.bodyParser());

var appRoutes = {
	// pages:
	page_error: "/error"
	, page_login: "/oauth2/login"
	, page_account: "/oauth2/account"
	, page_scopes: "/oauth2/scopes"
	// processes:
	, process_logout: "/oauth2/logout"
	, process_auth: "/oauth2/auth"
	, process_login: "/oauth2/do-login"
	, process_scopes: "/oauth2/do-scopes"
	, process_deauth: "/oauth2/deauth"
	, process_token: "/oauth2/token"
};
var oauth2Server = (new OAuth2Server({
	storageAdapter: new StorageAdapter( process.env.MONGOLAB_URI || "mongod://127.0.0.1:27017/oauth2-server-test" )
	, webAdapter: new WebAdapter( appRoutes ) })).start(
		function() { app.listen(3000); util.puts( " -> Application started on port 3000." ); }
		, function( err ) { util.puts("Can't connect to the storage adapter. Can't continue. Error: " + JSON.stringify(err)); } );

app.get(oauth2Server.webAdapter.routes.page_error, oauth2Server.webAdapter.page_errorHandler);
app.get(oauth2Server.webAdapter.routes.page_login, oauth2Server.webAdapter.page_loginHandler);
app.get(oauth2Server.webAdapter.routes.page_account, oauth2Server.webAdapter.page_accountHandler);
app.get(oauth2Server.webAdapter.routes.page_scopes, oauth2Server.webAdapter.page_scopesHandler);
app.get(oauth2Server.webAdapter.routes.process_logout, oauth2Server.webAdapter.process_logoutHandler);
app.get(oauth2Server.webAdapter.routes.process_auth, oauth2Server.webAdapter.process_authHandler);
app.post(oauth2Server.webAdapter.routes.process_login, oauth2Server.webAdapter.process_loginHandler);
app.post(oauth2Server.webAdapter.routes.process_scopes, oauth2Server.webAdapter.process_scopesHandler);
app.get(oauth2Server.webAdapter.routes.process_deauth, oauth2Server.webAdapter.process_deauthorizeAppHandler);
app.post(oauth2Server.webAdapter.routes.process_token, oauth2Server.webAdapter.process_tokenHandler);
