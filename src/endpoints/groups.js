const authz = require("../authz");
const {Group} = require("../groups");


const setGroup = (nameExtractor) => (req, res, next) => {
  const group = new Group(nameExtractor(req));

  authz.assertAuthorized(req.user, authz.actions.Read, group);

  req.context.group = group;
  return next();
};


module.exports = {
  setGroup,
};
