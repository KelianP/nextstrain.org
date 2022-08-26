const authz = require("../authz");
const {Group} = require("../groups");

const {contentTypesProvided, contentTypesConsumed} = require("../negotiate");
const {deleteByUrls, proxyFromUpstream, proxyToUpstream} = require("../upstream");


const setGroup = (nameExtractor) => (req, res, next) => {
  const group = new Group(nameExtractor(req));

  // No authorization is checked here. To be done by specific endpoints.

  req.context.group = group;
  return next();
};


/* Group customizations
 */


/* Group overview
 */


/* GET
 */
const getGroupOverview = contentTypesProvided([
  ["text/markdown", sendGroupOverview],
  ["text/plain", sendGroupOverview],
]);


/* PUT
 */
const putGroupOverview = contentTypesConsumed([
  ["text/markdown", receiveGroupOverview],
]);


/* DELETE
 */
const deleteGroupOverview = async (req, res) => {
  authz.assertAuthorized(req.user, authz.actions.Write, req.context.group);

  const method = "DELETE";
  const url = await req.context.group.source.urlFor("group-overview.md", method);
  await deleteByUrls([url]);

  return res.status(204).end();
};


/**
 * An Express endpoint that sends a group overview determined by the request.
 *
 * @param {express.request} req - Express-style request instance
 * @param {express.response} res - Express-style response instance
 * @returns {expressEndpointAsync}
 */
async function sendGroupOverview(req, res) {
  authz.assertAuthorized(req.user, authz.actions.Read, req.context.group);

  return await proxyFromUpstream(req, res,
    await req.context.group.source.urlFor("group-overview.md"),
    "text/markdown"
  );
}


/**
 * An Express endpoint that receives a group overview determined by the request.
 *
 * @param {express.request} req - Express-style request instance
 * @param {express.response} res - Express-style response instance
 * @returns {expressEndpointAsync}
 */
async function receiveGroupOverview(req, res) {
  authz.assertAuthorized(req.user, authz.actions.Write, req.context.group);

  return await proxyToUpstream(req, res,
    async (method, headers) => await req.context.group.source.urlFor("group-overview.md", method, headers),
    "text/markdown"
  );
}


module.exports = {
  setGroup,
  getGroupOverview,
  putGroupOverview,
  deleteGroupOverview,
};
