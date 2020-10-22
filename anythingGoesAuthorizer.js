//Anything goes authorizer

'use strict';

const generatePolicy = function(principalId, effect, resource) {
    console.log(resource)

    const authResponse = {};
    authResponse.principalId = principalId;
    if (effect && resource) {
        const policyDocument = {};
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        const statementOne = {};
        statementOne.Action = 'execute-api:Invoke';

        statementOne.Effect = effect;
        resource = "*"
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    return authResponse;
};

exports.handler = (event, context, callback) => {

    console.log("Hit Authorizer")

    callback(null, generatePolicy('user123', 'Allow', event.methodArn));
    
}; 


