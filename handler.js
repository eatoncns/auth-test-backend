const jwt = require('jsonwebtoken');

// Set in `enviroment` of serverless.yml
const { AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET } = process.env;

// Policy helper function
const generatePolicy = (principalId, effect, resource) => {
  const authResponse = {};
  authResponse.principalId = principalId;
  if (effect && resource) {
    const policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [];
    const statementOne = {};
    statementOne.Action = 'execute-api:Invoke';
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
};

// Reusable Authorizer function, set on `authorizer` field in serverless.yml
module.exports.auth = (event, context, callback) => {
  if (!event.authorizationToken) {
    return callback('Unauthorized');
  }

  const tokenParts = event.authorizationToken.split(' ');
  const tokenValue = tokenParts[1];

  if (!(tokenParts[0].toLowerCase() === 'bearer' && tokenValue)) {
    // no auth token!
    return callback('Unauthorized');
  }
  const options = {
    audience: AUTH0_CLIENT_ID,
  };
  // decode base64 secret. ref: http://bit.ly/2hA6CrO
  const secret = Buffer.from(AUTH0_CLIENT_SECRET, 'base64');
  try {
    jwt.verify(tokenValue, secret, options, (verifyError, decoded) => {
      if (verifyError) {
        // 401 Unauthorized
        return callback('Unauthorized');
      }
      // is custom authorizer function
      return callback(null, generatePolicy(decoded.sub, 'Allow', event.methodArn));
    });
  } catch (err) {
    return callback('Unauthorized');
  }
  return callback('Unauthorized');
};

// Public API
module.exports.publicEndpoint = (event, context, callback) => callback(null, {
  statusCode: 200,
  headers: {
    /* Required for CORS support to work */
    'Access-Control-Allow-Origin': '*',
    /* Required for cookies, authorization headers with HTTPS */
    'Access-Control-Allow-Credentials': true,
  },
  body: JSON.stringify({
    message: 'Hi ⊂◉‿◉つ from Public API',
  }),
});

// Private API
module.exports.privateEndpoint = (event, context, callback) => callback(null, {
  statusCode: 200,
  headers: {
    /* Required for CORS support to work */
    'Access-Control-Allow-Origin': '*',
    /* Required for cookies, authorization headers with HTTPS */
    'Access-Control-Allow-Credentials': true,
  },
  body: JSON.stringify({
    message: 'Hi ⊂◉‿◉つ from Private API. Only logged in users can see this',
  }),
});
