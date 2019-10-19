exports.authorizer = async function (event) {
    const queryStringParams = event.queryStringParameters.auth;
    const header = event.headers.approval;
    
    const methodArn = event.methodArn;

    if (header === 'approve' && queryStringParams === 'yes')
        return generateAuthResponse('user', 'Allow', methodArn);
    else
        return generateAuthResponse('user', 'Deny', methodArn);
}

function generateAuthResponse(principalId, effect, methodArn) {
    const policyDocument = generatePolicyDocument(effect, methodArn);

    return {
        principalId,
        policyDocument
    }
}

function generatePolicyDocument(effect, methodArn) {
    if (!effect || !methodArn) return null

    const policyDocument = {
        Version: '2012-10-17',
        Statement: [{
            Action: 'execute-api:Invoke',
            Effect: effect,
            Resource: methodArn
        }]
    };

    return policyDocument;
}