/**
 * Cognito user pool (IdP) management.
 *
 * @module cognito
 */
/* eslint-disable no-await-in-loop */
const {
  CognitoIdentityProviderClient,
  AdminAddUserToGroupCommand,
  AdminRemoveUserFromGroupCommand,
  paginateListUsersInGroup,
  UserNotFoundException,
} = require("@aws-sdk/client-cognito-identity-provider");
const {NotFound} = require("http-errors");


const COGNITO_USER_POOL_ID = "us-east-1_Cg5rcTged";
const REGION = COGNITO_USER_POOL_ID.split("_")[0];

const cognito = new CognitoIdentityProviderClient({ region: REGION });


/**
 * Retrieve AWS Cognito users in a Cognito group.
 *
 * @param {string} name - Name of the AWS Cognito group
 * @yields {object} user, see <https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/clients/client-cognito-identity-provider/interfaces/usertype.html>
 */
async function* listUsersInGroup(name) {
  const paginator = paginateListUsersInGroup({client: cognito}, {
    UserPoolId: COGNITO_USER_POOL_ID,
    GroupName: name,
  });

  for await (const page of paginator) {
    yield* page.Users;
  }
}


/**
 * Add an AWS Cognito user to a Cognito group.
 *
 * @param {string} username
 * @param {string} group - Name of the AWS Cognito group
 * @throws {NotFound} if username is unknown
 */
async function addUserToGroup(username, group) {
  try {
    await cognito.send(new AdminAddUserToGroupCommand({
      UserPoolId: COGNITO_USER_POOL_ID,
      Username: username,
      GroupName: group,
    }));
  } catch (err) {
    if (err instanceof UserNotFoundException) {
      throw new NotFound(`unknown user: ${username}`);
    }
    throw err;
  }
}


/**
 * Remove an AWS Cognito user from a Cognito group.
 *
 * @param {string} username
 * @param {string} group - Name of the AWS Cognito group
 * @throws {NotFound} if username is unknown
 */
async function removeUserFromGroup(username, group) {
  try {
    await cognito.send(new AdminRemoveUserFromGroupCommand({
      UserPoolId: COGNITO_USER_POOL_ID,
      Username: username,
      GroupName: group,
    }));
  } catch (err) {
    if (err instanceof UserNotFoundException) {
      throw new NotFound(`unknown user: ${username}`);
    }
    throw err;
  }
}


module.exports = {
  listUsersInGroup,
  addUserToGroup,
  removeUserFromGroup,
};
