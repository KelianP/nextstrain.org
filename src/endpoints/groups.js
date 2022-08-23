const {NotFound} = require("http-errors");

const authz = require("../authz");
const {Group} = require("../groups");
const {slurp} = require("../utils/iterators");


const setGroup = (nameExtractor) => (req, res, next) => {
  const group = new Group(nameExtractor(req));

  authz.assertAuthorized(req.user, authz.actions.Read, group);

  req.context.group = group;
  return next();
};


const listMembers = async (req, res) => {
  const group = req.context.group;

  authz.assertAuthorized(req.user, authz.actions.Read, group);

  return res.json(await group.members());
};


const listRoles = (req, res) => {
  const group = req.context.group;

  authz.assertAuthorized(req.user, authz.actions.Read, group);

  const roles = [...group.membershipRoles.keys()];
  return res.json(roles.map(name => ({name})));
};


const listRoleMembers = async (req, res) => {
  const group = req.context.group;
  const {roleName} = req.params;

  authz.assertAuthorized(req.user, authz.actions.Read, group);

  return res.json(await slurp(group.membersWithRole(roleName)));
};


const getRoleMember = async (req, res) => {
  const group = req.context.group;
  const {roleName, username} = req.params;

  authz.assertAuthorized(req.user, authz.actions.Read, group);

  for await (const member of group.membersWithRole(roleName)) {
    if (member.username === username) {
      return res.status(204).end();
    }
  }

  throw new NotFound(`user ${username} does not have role ${roleName} in group ${group.name}`);
};


const putRoleMember = async (req, res) => {
  const group = req.context.group;
  const {roleName, username} = req.params;

  authz.assertAuthorized(req.user, authz.actions.Write, group);

  await group.grantRole(roleName, username);

  return res.status(204).end();
};


const deleteRoleMember = async (req, res) => {
  const group = req.context.group;
  const {roleName, username} = req.params;

  authz.assertAuthorized(req.user, authz.actions.Write, group);

  await group.revokeRole(roleName, username);

  return res.status(204).end();
};


module.exports = {
  setGroup,

  listMembers,
  listRoles,
  listRoleMembers,

  getRoleMember,
  putRoleMember,
  deleteRoleMember,
};
