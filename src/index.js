const AWS    = require('aws-sdk');
const crypto = require('crypto');
const jws    = require('jws');
const uuid   = require('uuid');

AWS.config.region = process.env.AWS_REGION;

const dynamodb = new AWS.DynamoDB();
const kms      = new AWS.KMS();

function getRequest(event) {
    var res = event.queryStringParameters || {};

    if ((event.httpMethod == "POST" || event.httpMethod == "PUT") && event.headers) {
        var contentType = null;

        for (i in event.headers) {
            if (i.toLowerCase() == "content-type") {
                contentType = event.headers[i].split(";")[0]
                break;
            }
        }

        if (contentType == "application/json") {
            var bodyData = JSON.parse(event.body)

            for (var i in bodyData) {
                res[i] = bodyData[i]
            }
        }
    }

    return res;
}

function getMyId(event, callback) {
    if (!event.requestContext || !event.requestContext.authorizer || !event.requestContext.authorizer.Id) {
        callback(null, {
            statusCode: 401,
            body: JSON.stringify({
                error: "Unauthorized"
            })
        })
        return null
    }
    return event.requestContext.authorizer.Id
}

exports.verify = (event, context, callback) => {
    var token = event.authorizationToken;

    var kmsParams = {
        CiphertextBlob: new Buffer(process.env.ZOXO_JWT_SGNING_KEY, 'base64')
    }

    kms.decrypt(kmsParams, (err, data) => {
        if (err) {
            console.error(err)
            return context.fail(err)
        }

        if (!jws.verify(token, 'HS256', data.Plaintext)) {
            console.error({error: "Invalid token", token: token})
            return context.fail("Invalid token");
        }

        var tokenData = jws.decode(token)

        var kmsPayloadParams = {
            CiphertextBlob: new Buffer(tokenData.payload, 'base64')
        }

        kms.decrypt(kmsPayloadParams, (err, data) => {
            if (err) {
                console.log(err);
                return context.fail("Cannot decrypt token");
            }

            var payload;
            try {
                payload = JSON.parse(data.Plaintext)
            } catch(e) {
                console.log({error: "Invalid token payload", tokenData: tokenData, exception: e})
                return context.fail("Invalid token payload");
            }

            var [,,, region, accountId, resource] = event.methodArn.split(':');
            var [restApiId, stage] = resource.split('/');

            var statement = {
                Action: ["execute-api:Invoke"],
                Effect: "Allow",
                Resource: ["arn:aws:execute-api:" + region + ":" + accountId + ":" + restApiId + "/*/*"]
            }

            var policy = {
                Version: '2012-10-17',
                Statement: [statement],
            }

            var authResponse = {
                principalId: payload.Id,
                policyDocument: policy,
                context: payload,
            }

            console.log(JSON.stringify(authResponse))
            callback(null, authResponse)
        })
    })
}

exports.register = (event, context, callback) => {
    var request = getRequest(event);

    var email = typeof(request.email) == "string" && request.email.trim() || ""
    var password = typeof(request.password) == "string" && request.password || ""
    var name = typeof(request.name) == "string" && request.name.trim() || ""

    if (!email.match(/^[A-Za-z0-9-_.]+@[A-Za-z0-9-_.]+$/)) {
        return callback(null, {
            statusCode: 400,
            body: JSON.stringify({
                error: "Email address is invalid"
            })
        })
    }

    if (password.length < 6) {
        return callback(null, {
            statusCode: 400,
            body: JSON.stringify({
                error: "Password is too short"
            })
        })
    }

    if (!name.length) {
        return callback(null, {
            statusCode: 400,
            body: JSON.stringify({
                error: "Name is empty"
            })
        })
    }

    var hmac = crypto.createHmac('sha256', '')
    hmac.update(password)
    var passwordHash = hmac.digest('hex')

    var dynamoParams = {
        Item: {
            Id: {
                S: uuid.v4()
            },
            Email: {
                S: email
            },
            PasswordHash: {
                S: passwordHash
            },
            Name: {
                S: name
            }
        },
        TableName: process.env.ZOXO_DYNAMO_TABLE_USER,
        ConditionExpression: "attribute_not_exists(Email)",
    };

    dynamodb.putItem(dynamoParams, (err, data) => {
        if (err && err.code == 'ConditionalCheckFailedException') {
            // User already exists
            return callback(null, {
                statusCode: 400,
                body: JSON.stringify({
                    error: "User already exists"
                })
            })
        } else if (err) {
            console.error(err)
            return callback("Unexpected error")
        }

        callback(null, {
            statusCode: 200,
            body: JSON.stringify({
                ok: true,
                data: {
                    Id: dynamoParams.Item.Id.S,
                }
            })
        })
    })
}

exports.login = (event, context, callback) => {
    var request = getRequest(event);

    var email = typeof(request.email) == "string" && request.email.trim()
    var password = typeof(request.password) == "string" && request.password

    if (!email || !password) {
        return callback(null, {
            statusCode: 400,
            body: JSON.stringify({
                error: "Malformed email or password"
            })
        })
    }

    var hmac = crypto.createHmac('sha256', '')
    hmac.update(password)
    var passwordHash = hmac.digest('hex')

    var dynamoParams = {
      Key: {
        "Email": {
          S: email
        }
      },
      TableName: process.env.ZOXO_DYNAMO_TABLE_USER
    }

    dynamodb.getItem(dynamoParams, (err, user) => {
        if (err) {
            console.error(err)
            return callback("Unexpected error")
        } else if (!user.Item || !user.Item.PasswordHash || user.Item.PasswordHash.S !== passwordHash) {
            return callback(null, {
                statusCode: 403,
                body: JSON.stringify({
                    error: "User not found"
                })
            })
        }

        var kmsParams = {
            CiphertextBlob: new Buffer(process.env.ZOXO_JWT_SGNING_KEY, 'base64')
        };

        kms.decrypt(kmsParams, (err, key) => {
            if (err) {
                console.error(err)
                return callback("Unexpected error")
            }

            var payload = {
                Id:    user.Item.Id.S,
                Email: user.Item.Email.S,
                Name:  user.Item.Name.S
            }

            var kmsEncryptParams = {
                KeyId: process.env.ZOXO_KMS_KEY_ID,
                Plaintext: JSON.stringify(payload),
            }

            kms.encrypt(kmsEncryptParams, (err, payload) => {
                var token = jws.sign({payload: payload.CiphertextBlob.toString('base64'), secret: key.Plaintext, header: {alg: 'HS256'}});

                callback(null, {
                    statusCode: 200,
                    headers: {
                        Authorization: "Bearer " + token,
                    },
                    body: JSON.stringify({
                        ok: true,
                        data: {
                            token: token
                        }
                    })
                })
            })
        })
    })
}

exports.user = (event, context, callback) => {
    var myId = getMyId(event, callback);


    var request = getRequest(event);

    var userId = myId;

    if (request.UserId && typeof(request.UserId) == "string") {
        userId = request.UserId
    }

    var params = {
        TableName: process.env.ZOXO_DYNAMO_TABLE_USER,
        IndexName: process.env.ZOXO_DYNAMO_TABLE_USER_ID_INDEX,
        KeyConditionExpression: "Id = :Id",
        ExpressionAttributeValues: {
            ":Id": {S: userId}
        },
    }

    dynamodb.query(params, (err, data) => {
        if (err) {
            console.error(err)
            return callback("Unexpected error")
        }

        if (!data || !data.Items || !data.Items.length) {
            return callback(null, {
                statusCode: 404,
                body: JSON.stringify({
                    error: "User not found"
                })
            })
        }

        var userObj = data.Items[0]

        var user = {
            Id: userObj.Id.S,
            Name: userObj.Name.S,
        }

        if (user.Id == myId) {
            user.Email = userObj.Email.S
        }

        callback(null, {
            statusCode: 200,
            body: JSON.stringify({
                ok: true,
                data: user,
            })
        })
    })
}
