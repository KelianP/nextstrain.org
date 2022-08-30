const authz = require("../authz");
const {Group} = require("../groups");


const setGroup = (nameExtractor) => (req, res, next) => {
  const group = new Group(nameExtractor(req));

  // No authorization is checked here. To be done by specific endpoints.

  req.context.group = group;
  return next();
};


module.exports = {
  setGroup,
};
