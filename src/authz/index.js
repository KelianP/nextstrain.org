const assert = require("assert").strict;

const {AuthzDenied} = require("../exceptions");

const actions = require("./actions");
const tags = require("./tags");

/**
 * Checks if a user is allowed to take an action on an object.
 *
 * This is the main authorization routine called from throughout the codebase
 * (often via {@link assertAuthorized}).
 *
 * @param {module:../authn.User} user - Subject or principal doing the acting.
 * @param {Symbol} action - Action being taken, from {@link module:./actions}.
 * @param {object} object - Object being acted upon.
 * @returns {boolean}
 */
const authorized = (user, action, object) => {
  // user may be null
  assert(!user || user.authzRoles != null, "user.authzRoles is not null if user is not null");
  assert(actions.has(action), "action is known");
  assert(object != null, "object is not null");

  /* As a safe guard, anonymous users can only ever read, regardless of
   * policies right now.  We don't have any use cases right now where letting
   * anonymous users modify things is correct.
   */
  if (!user && action !== actions.Read) {
    return false;
  }

  /* Determine what policy is in force based on the object.  Currently we scope
   * policies to the source-level, but in the future we could easily adjust the
   * level at which policies reside and even combine multiple policies (e.g. a
   * policy from the source and a global policy).  The case table nicely
   * self-documents what kinds of objects we support here.
   *
   * I chose not to take the alternative, object-oriented approach of just
   * calling "object.authzPolicy" blindly and expecting "object" to determine
   * the policy in force itself, e.g. by Resources delegating to their
   * containing Source's authzPolicy.  That alternative approach also comes
   * with the pitfall/misfeature of easily permitting implementation of
   * per-dataset policies, which I think we want to avoid in favor of
   * per-dataset tags + higher-level policies (i.e. at Source/Group level)
   * which scope actions to those tags.  It could be worth reconsidering if
   * this case table grows out of hand, but I expect that to happen
   * approximately never.
   *    -trs, 4 Jan 2022
   */
  /* eslint-disable indent, no-multi-spaces, semi-spacing, no-use-before-define */
  const policy =
    object instanceof Group    ? object.authzPolicy        :
    object instanceof Source   ? object.authzPolicy        :
    object instanceof Resource ? object.source.authzPolicy :
                                                      null ;
  /* eslint-enable no-use-before-define */

  const objectTags = object.authzTags;
  const userRoles = user ? user.authzRoles : new Set();

  return evaluatePolicy(policy, userRoles, action, objectTags); // eslint-disable-line no-use-before-define
};


/**
 * Evaluates *policy* using the given *userRoles*, *action*, and *objectTags*.
 *
 * Returns true when the policy permits and false otherwise.
 *
 * @param {Object[]} policy - Array of rules to evaluate.
 * @param {Set} userRoles - Roles of user taking action.
 * @param {Symbol} action - Action being taken, from {@link module:./actions}.
 * @param {Set} objectTags - Tags of object being acted upon.
 * @returns {boolean}
 */
const evaluatePolicy = (policy, userRoles, action, objectTags) => {
  assert(Array.isArray(policy));
  assert(policy.every(({tag, role, allow}) => tag && role && allow));
  assert(objectTags instanceof Set);
  assert(userRoles instanceof Set);
  assert(actions.has(action), "action is known");

  /* Policy rules apply to this (user, object) combo if the user roles and
   * object tags match those specified by the rule, or the rule uses a
   * wildcard.
   */
  const applicablePolicyRule = ({tag, role}) =>
       tag && role
    && (tag  === "*" || objectTags.has(tag))
    && (role === "*" || userRoles.has(role));

  /* eslint-enable indent, no-multi-spaces, semi-spacing */

  /* If we need/want to support "deny" policy rules in the future, this is the
   * place to do it.
   *    -trs, 4 Jan 2022
   */
  const allowed = new Set(
    policy
      .filter(applicablePolicyRule)
      .flatMap(({allow}) => allow)
  );

  return allowed.has(action);
};


/**
 * Throws an exception if calling {@link authorized} with the given (user,
 * action, object) returns false.
 *
 * @param {module:../authn.User} user - Subject or principal doing the acting.
 * @param {Symbol} action - Action being taken, from {@link module:./actions}.
 * @param {object} object - Object being acted upon.
 * @throws {AuthzDenied}
 */
const assertAuthorized = (user, action, object) => {
  if (!authorized(user, action, object)) {
    throw new AuthzDenied();
  }
};


/**
 * Express-style middleware that calls {@link assertAuthorized} with the (user,
 * action, object) produced from the request by the given extractor function.
 *
 * @param {argsExtractor} argsExtractor - Function to extract (user, action,
 *   object) array from the request
 * @returns {expressMiddleware}
 * @throws {AuthzDenied}
 */
const assertAuthorizedReq = (argsExtractor) => (req, res, next) => {
  assertAuthorized(...argsExtractor(req));
  return next();
};

/**
 * @callback argsExtractor
 * @param {express.request} req
 * @returns {Array} args - three element array of (user, action, object)
 */


module.exports = {
  authorized,
  assertAuthorized,
  assertAuthorizedReq,
  evaluatePolicy,

  actions,
  tags,
};


/* Import these after we declare exports to avoid circular import issues, as
 * these modules also import this module.  I think this would be unnecessary if
 * we used ESM "export" declarations here instead of the CommonJS
 * "module.exports", but converting this to use ESM is a change with broader
 * impact (although a change I'd like to make more broadly in this codebase at
 * some point sooner than later).
 *   -trs, 3 Aug 2022
 */
const {Group} = require("../groups");
const {Source, Resource} = require("../sources/models");
