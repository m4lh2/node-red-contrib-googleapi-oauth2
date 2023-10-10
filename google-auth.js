module.exports = function(RED) {
    "use strict";
    const crypto = require("crypto");
    const url = require('url');
    const { google } = require('googleapis');
    const { OAuth2Client } = require('google-auth-library');
    const http = require('http');

    function GoogleNode(n) {
        RED.nodes.createNode(this,n);
        this.displayName = n.displayName;
        this.scopes = n.scopes;
    }

    RED.nodes.registerType("google-credentials",GoogleNode,{
        credentials: {
            displayName: {type:"text"},
            clientId: {type:"text"},
            clientSecret: {type:"password"},
            accessToken: {type:"password"},
            refreshToken: {type:"password"},
            expireTime: {type:"password"}
        }
    });
    
    RED.httpAdmin.get('/google-credentials/auth', function(req, res){
        console.log('google-credentials/auth');

        const clientId = req.query.clientId;
        const clientSecret = req.query.clientSecret;
        const callbackUri = req.query.callback;
        const nodeId = req.query.id;
        const scopes = req.query.scopes;

        console.log('Callback URI:', callbackUri);

        // Add a credentials node, with the secret and id
        // the rest of the data (access/refresh token etc) will be assigned when google returns them.
        const credentials = {
            clientId : clientId,
            clientSecret: clientSecret,
            // This is needed later to re-open the client
            callbackUri: callbackUri
        };

        RED.nodes.addCredentials(nodeId, credentials);

        // create an oAuth client to authorize the API call.
        const oAuth2Client = new OAuth2Client(
            clientId,
            clientSecret,
            // This has to match the url in the browser window.
            callbackUri
        );

        // Generate the url that will be used for the consent dialog.
        const authorizeUrl = oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: scopes,
            // Add some data here that will be returned to us in the callback
            // we need nodeId to access our credentials node and update it.
            state: nodeId + ':' + crypto.randomBytes(20).toString('base64')
        });

        // navigate to googles oauth page.
        res.redirect(authorizeUrl);
    });

    // Googles OAuth will respond at this URL with a code in the url
    // this token needs to be used to get the access token.
    // the token is refreshed by the main google node.
    RED.httpAdmin.get('/google-credentials/auth/callback', function(req, res){
        console.log('google-credentials/auth/callback');

        // pull out the nodeId data we put in the state field in the auth request
        // and get the credentials node.
        var state = req.query.state.split(':');
        var nodeId = state[0];

        var credentials = RED.nodes.getCredentials(nodeId);

        // Create the client again, with the same parameters, and get tokens now 
        // that we have a code from google.
        const oauth2Client = new OAuth2Client(
            credentials.clientId,
            credentials.clientSecret,
            credentials.callbackUri
        );

        oauth2Client.getToken(req.query.code)
        .then((value) => {
            // Save new tokens
            credentials.accessToken = value.tokens.access_token;
            credentials.refreshToken = value.tokens.refresh_token;
            credentials.expireTime = value.tokens.expiry_date;
            credentials.tokenType = value.tokens.token_type;
            credentials.displayName = value.tokens.scope.substr(0, 40);
        });

        RED.nodes.addCredentials(nodeId, credentials);

        res.send('Authorized');
    });
};