const authz = require("../authz");
const {ALL_GROUPS} = require("../groups");
const {contentTypesProvided} = require("../negotiate");
const {sendGatsbyPage} = require("./static");


/**
 * Returns an array of Nextstrain groups that are visible to a
 * given *user* (or a non-logged in user). The order of groups returned
 * matches the order in `data/groups.json`.
 *
 * @param {Object | undefined} user. `undefined` represents a non-logged-in user
 * @returns {Array} Each element is an object with keys `name` -> {str} (group name) and
 *                  `private` -> {bool} (group is private)
 */
const visibleGroups = (user) => ALL_GROUPS
  .map(g => [g.name, g.source])
  .filter(([, source]) => authz.authorized(user, authz.actions.Read, source))
  .map(([name, source]) => ({
    name,
    private: !authz.authorized(null, authz.actions.Read, source),
  }));


// Provide the client-side app with info about the current user
const getWhoami = contentTypesProvided([
  ["html", sendGatsbyPage("whoami/index.html")],
  ["json", (req, res) =>
    // Express's JSON serialization drops keys with undefined values
    res.json({
      user: req.user || null,
      visibleGroups: visibleGroups(req.user),
    })
  ],
]);


module.exports = {
  getWhoami,
};
