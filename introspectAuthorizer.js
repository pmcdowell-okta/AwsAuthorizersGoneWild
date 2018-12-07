'use strict';

const request = require('request');
const jws = require('jws');
const jwk2pem = require('pem-jwk').jwk2pem;

const handlers = module.exports = {};

module.exports.jwtVerifyIntrospect = (event, context, callback) =>
{

    console.log("starting")

    if (!event.authorizationToken) {
        console.log("Header does not exist not exist")
        badToken(callback)
        return;

    }

    var token = event.authorizationToken; //This token is passed in header of request
    console.log(token)


    token = token.replace(/^Bearer /, '');
    token = token.replace(/^bearer /, ''); // Just incase someoen forgets to capatalize

    const decoded = jws.decode(token);

    if (!decoded) {
        console.log("Bad Token")
        badToken(callback)
        return;
    } else {

        const claims = safelyParseJSON(decoded.payload);

        if (!claims.iss ) {
            // console.log("no claims found")

        } else {

            /*
            This code pulls the keys at runtime, which is not optimal.
            Ideally, the keys should be pinned or cached for better Much performance

            Also, the code will permit any Okta Token, in production this should not be used, but
            it works fine for test.

             */
            if ((claims.iss.split("\/").length == 5)) {
                console.log("API Access Mgmt token")
                var introspectUrl = claims.iss + "/v1/introspect"

            } else {
                console.log("OIDC endpoint")
                var introspectUrl = claims.iss + "/oauth2/v1/introspect"
            }


            var requestObj = {};
            requestObj.introspectUrl = introspectUrl
            requestObj.token = token
            requestObj.callback = callback
            requestObj.event = event

            introspectToken(requestObj).then( (result)=> {
                // Alright, we got the response from Okta... 
                
                var finalResponse = JSON.parse(result.response)

                // console.log(result.callback)


                if(finalResponse.active) {
                    goodToken(result.event.methodArn, result.callback)
                }
                //     badToken(callback)
                // }
                //
                //
                //
                // console.log("done...")


            })
        }
    }
};

function badToken ( cb ){
    cb('No Token');
}

function goodToken(arn, cb) {
    cb(null, {
        principalId: "patrickmcdowell",
        policyDocument: {
            Version: '2012-10-17',
            Statement: [{
                Action: 'execute-api:Invoke',
                Effect: "Allow",
                Resource: arn
            }]
        }
    });
}

var introspectToken= function (requestObj) {
    return new Promise((resolve, reject) => {

        var request = require("request");

        console.log(requestObj);


        var options = { method: 'POST',
            url: requestObj.introspectUrl,
            qs:
                { token: requestObj.token,
                    token_type_hint: 'id_token',
                    grant_type: '' },
            headers:
                { 'postman-token': 'f58f94c9-2b0d-48bb-06a1-c73110ec23ab',
                    'cache-control': 'no-cache',
                    authorization: 'Basic dlpWNkNwOHJuNWx4ck45YVo2ODg6djJHTGViSVJPQ0oyMXJBVG9tVDVKeVdUak4yUTJYbFlLcHlZb1ZVUw==',
                    accept: 'application/json',
                    'content-type': 'application/x-www-form-urlencoded' } };

        request(options, function (error, response, body) {
            if (error) throw new Error(error);
            requestObj.response = body;
            resolve(requestObj)
        });
    })
}



function safelyParseJSON (json) {
    var parsed

    try {
        parsed = JSON.parse(json)
    } catch (e) {
        // Oh well, but whatever...
    }
    return parsed // Could be undefined!
}



//Uncomment this if you want to test the Lambda locally
//
//
// var event = {authorizationToken: "Bearer eyJraWQiOiJDN3lzVUlSRXBvTy1lRktRRFlmaXcxRERVcldRZENjTVZYRUd1RWxkanBZIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiIwMHUxOGVlaHUzNDlhUzJ5WDFkOCIsIm5hbWUiOiJva3RhcHJveHkgb2t0YXByb3h5IiwidmVyIjoxLCJpc3MiOiJodHRwczovL2NvbXBhbnl4Lm9rdGEuY29tIiwiYXVkIjoidlpWNkNwOHJuNWx4ck45YVo2ODgiLCJpYXQiOjE1NDM4NjIxMzcsImV4cCI6MTU0Mzg2NTczNywianRpIjoiSUQuY2k0LTMxUk5Ca0dUQ0s1eWwtc2hNUG52dmwzanU0TGh3Znl6QXMzZXRzUSIsImFtciI6WyJwd2QiXSwiaWRwIjoiMDBveTc0YzBnd0hOWE1SSkJGUkkiLCJub25jZSI6Im4tMFM2X1d6QTJNaiIsInByZWZlcnJlZF91c2VybmFtZSI6Im9rdGFwcm94eUBva3RhLmNvbSIsImF1dGhfdGltZSI6MTU0Mzg1Njg4MywiYXRfaGFzaCI6Ii1vTENiaGRiNVd6Wld1aWJ6UG5VMHcifQ.WsqlWomOPnJpx-jge5Abal5OSdM_XMoLsaE6Mv36LRkx2QGo_iiLzx_Z_rE_yuK5HS0gZG7WOw8fgpdWoFdD0wvBGiEsw5j5bct81gF_wm1Wzb18sjWm9Uy3wht7WDJxB6BXxQZqVX-fDZMFqbd4A2J9KOs84u7b-ySltvlNXi0sOBiUGT93HXYkYK5nxOfrLSGi3wlphHQydHUI4O5Ehgj3u5cQDGAg3wBY5DVkTIXeJxNT_A2GsFpxQJFSmDt1A_o1i3EXSiuEfRHMmKN5B56K2dPZX9_FdwQL9cd1eYkVsuAc3D4WolehOHw872mzUTFZdIHyhxl-LtGbPStQEA"};
//
// module.exports.jwtVerifyIntrospect ( event, {}, function( code, result) {
//     console.log(result)
//
// })


