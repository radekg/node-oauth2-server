# OAuth2 server blueprint for Node.js

## Standards

This project aims to be compatible with a OAuth 2 draft 10 standard (<http://tools.ietf.org/html/draft-ietf-oauth-v2-10>)

## So what exactly is it?

It's not only a standard implementation. This project tries to be a blueprint for an OAuth2 server. It depends on Express.js and MongoDB to provide HTTP / storage layers. Based on OAuth2 draft 10, it is still influenced by existing implementations, specially Google Oauth2 and Facebook. Some implementation details may differ from the IETF draft.

## What's included

* issuing an auth_code
* issuing an authorization_code
* issuing a refresh_token
* scope handling
* scope allow / deny
* login / logout
* app deauth

## What is this stuff developed with

* Node.js 0.6.12 (if using Heroku Cedar - <http://blog.superpat.com/2011/11/15/running-your-own-node-js-version-on-heroku/>)
	* expressjs <https://github.com/visionmedia/express>
	* jade <https://github.com/visionmedia/jade>
	* mongodb-native <https://github.com/christkv/node-mongodb-native>

The reason why latest Node is used is that I could;t really be bothered testing with versions between 0.4.7 (what Heroku uses) and the latest one. I know though the connect stuff this project uses (body parser / cookie parser / mongo session implementation) doesn't work with 0.4.7. And I'm running my own VPS, yes, I know, by I need my own writable LOCAL filesystem.

To get the connect session stuff working with mongodb - check this link <http://stackoverflow.com/a/9495689>.

## Quick start

Yep, coming, coming. For now just follow the oauth2-app.js.