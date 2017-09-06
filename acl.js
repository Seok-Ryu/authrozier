/*jshint camelcase: false*/
'use strict';

let logger = require('log4js').getLogger('AUTHORIZATION'),
    async = require('async'),
    Acl = require('acl'),
    _ = require('lodash');

let applib = require('../applib'),
    authenticator = require('../authenticator'),
    commonUtils = require('../utils'),
    DB_CFG = require('../applib/db_cfg.json'),
    ROLE_CFG = require('../role_cfg.json'),
    DWError = require('../response/error');

let PERMISSION_MAP = {
      post: 'c',
      get: 'r',
      put: 'u',
      delete: 'd'
    },
    SYSTEM_ADMIN_USER_DEFAULT_ROLE = 'user:0',
    PERMISSION_ALL = '*',//['c', 'r', 'u', 'd'];
    SYSTEM_ADMIN_DEFAULT_ROLE = 'systemAdmin',
    SERVICE_ADMIN_DEFAULT_ROLE = 'serviceAdmin',
    SITE_ADMIN_DEFAULT_ROLE = 'siteAdmin',
    DEFAULT_ROLE = 'default',
    USER_DEFAULT_ROLE_PREFIX = 'user:',
    USER_DEFAULT_ROLE = USER_DEFAULT_ROLE_PREFIX + '{id}',
    PREDEFINED_ROLE = [SYSTEM_ADMIN_DEFAULT_ROLE, SERVICE_ADMIN_DEFAULT_ROLE, SITE_ADMIN_DEFAULT_ROLE];

var COMPARED_METHOD = {
  GREATER: 'GREATER',
  GREATER_OR_EQUAL: 'GREATER_OR_EQUAL'
};

var acl;

function template(str, tokens) {
  return commonUtils.template(str, tokens);
}

function getSplitResources(resource) {
  var arr = resource.split('/'), resources = [];

  //Note: make lowercase to resource(for acl check). have to defined by lowercase on role_cfg
  if(arr[2]) {
    arr[2] = arr[2].toLowerCase();
  }

  for (var i = 0; i < arr.length - 1; i++) {
    resources.push(arr.slice(0, i + 2).join('/'));
  }

  return resources;
}

function getUserDefaultRoleId(userId) {
  return USER_DEFAULT_ROLE_PREFIX + userId;
}

function getUserDefaultRoles(id) {
  return [getUserDefaultRoleId(id), DEFAULT_ROLE];
}

function isEndUserRole(roleId) {
  return _.includes(roleId, USER_DEFAULT_ROLE_PREFIX);
}

function compareRoleLevel(targetRole, comparedRole, comparedMethod, cb) {
  var allRoles = _.union(PREDEFINED_ROLE, [DEFAULT_ROLE, _.first(USER_DEFAULT_ROLE_PREFIX.split(':'))]);

  var targetRoleIndex = _.findIndex(allRoles, function (role) {
    return _.isEqual(_.first(targetRole.split(':')), role);
  });

  var comparedRoleIndex = _.findIndex(allRoles, function (role) {
    return _.isEqual(_.first(comparedRole.split(':')), role);
  });

  if(targetRoleIndex === -1) {
    return DWError.newNotFound({message: targetRole + ' is can not find '}, cb);
  }

  if(comparedRoleIndex === -1) {
    return DWError.newNotFound({message: comparedRole + ' is can not find '}, cb);
  }

  switch (comparedMethod) {
    case COMPARED_METHOD.GREATER:
      return cb(null, targetRoleIndex < comparedRoleIndex);
    case COMPARED_METHOD.GREATER_OR_EQUAL:
      return cb(null, targetRoleIndex <= comparedRoleIndex);
    default:
      return DWError.newInvalidInput({message: 'comparedMethod is not defined', comparedMethod: comparedMethod}, cb);
  }
}

/**
 *
 * @param {string|array} role
 */
function getRolesPolicy(role, userId) {
  if(!role || !userId) {
    //Error case
    return [];
  }

  var newRoles;

  if(_.includes(role, SYSTEM_ADMIN_DEFAULT_ROLE) && _.isEqual(userId, '0')) {
    newRoles = [
      SYSTEM_ADMIN_DEFAULT_ROLE,
      SERVICE_ADMIN_DEFAULT_ROLE,
      SITE_ADMIN_DEFAULT_ROLE,
      DEFAULT_ROLE,
      getUserDefaultRoleId(userId)
    ];
  } else if(_.includes(role, SERVICE_ADMIN_DEFAULT_ROLE)) {
    newRoles = [
      SERVICE_ADMIN_DEFAULT_ROLE,
      SITE_ADMIN_DEFAULT_ROLE,
      DEFAULT_ROLE,
      getUserDefaultRoleId(userId)
    ];
  } else if(_.includes(role, SITE_ADMIN_DEFAULT_ROLE)) {
    newRoles = [
      SITE_ADMIN_DEFAULT_ROLE,
      DEFAULT_ROLE,
      getUserDefaultRoleId(userId)
    ];
  } else {
    //Note: case of end user default role
    newRoles = [
      DEFAULT_ROLE,
      getUserDefaultRoleId(userId)
    ];
  }

  return newRoles;
}

/**
 *
 * @param {string} userId - userId
 * @param {string|array} roleId - roleId or array of roleId
 * @param cb
 */
function addRoleToUser(userId, roleId, cb) {
  acl.addUserRoles(userId, roleId, function (err) {
    if (err) {
      return DWError.newLibraryError({
        lib: 'acl',
        methodName: 'addUserRoles',
        userId: userId,
        role: roleId
      }, err, cb);
    }

    return cb();
  });
}

function getUsersRoles(userId, cb) {
  acl.userRoles(userId, function (err, roles) {
    if (err) {
      err = DWError.newLibraryError({lib: 'acl', methodName: 'userRoles', userId: userId}, err);
    }

    return cb(err, roles);
  });
}

function hasTargetRole(userId, targetRole, cb) {
  acl.hasRole(userId, targetRole, function (err, hasRole) {
    if (err) {
      err = DWError.newLibraryError({lib: 'acl', methodName: 'hasRole', userId: userId, roleId: targetRole}, err);
    }

    return cb(err, hasRole);
  });
}

/**
 *
 * @param {string} userId - userId
 * @param {string|array} roleId - roleId or array of roleId
 * @param cb
 */
function removeRoleOfUser(userId, roleId, cb) {
  acl.removeUserRoles(userId, roleId, function (err) {
    if (err) {
      err = DWError.newLibraryError({lib: 'acl', methodName: 'removeUserRoles', userId: userId, roles: roleId}, err);
    }

    return cb(err);
  });
}

function updateRole(permissionsArray, cb) {
  acl.allow(permissionsArray, function (err) {
    if(err) {
      logger.error('[acl/updateRole] acl.allow fail', permissionsArray);
      return DWError.newLibraryError({lib: 'acl', methodName: 'allow', roleId: permissionsArray.roles}, err, cb);
    }

    logger.debug('[acl/updateRole] acl.allow success roles', permissionsArray);
    return cb();
  });
}

function getUserDefaultRoleAllows(roleId) {
  //Note: system admin's user default role must empty
  if(roleId === SYSTEM_ADMIN_USER_DEFAULT_ROLE) {
    return [];
  }

  var targetUserId = roleId.split(':')[1];
  var allows = [{
    'resources': '/api/users/' + targetUserId,
    'permissions': ['r', 'u']
  }];

  return _.union(ROLE_CFG[USER_DEFAULT_ROLE], allows);
}

function createRole(roleId, cb) {
  var permissionsArray = [];

  if(isEndUserRole(roleId)) {
    permissionsArray.push({
      roles: roleId,
      allows: getUserDefaultRoleAllows(roleId)
    });
  } else {
    permissionsArray.push({
      roles: roleId,
      allows: ROLE_CFG[roleId]
    });
  }

  return updateRole(permissionsArray, cb);
}

function deleteRole(roleId, cb) {
  acl.removeRole(roleId, function (err) {
    if(err) {
      logger.error('[acl/deleteRole] Remove Role: %s / err=', roleId, err);
      return DWError.newLibraryError({lib: 'acl', methodName: 'removeRole', roleId: roleId}, err, cb);
    }

    logger.info('Remove Role: %s', roleId);
    return cb();
  });
}

function updateAllRoles(cb) {
  var allRoles = _.union(PREDEFINED_ROLE, [DEFAULT_ROLE]);

  async.series([
    function __removeAllPreDefinedRole(done) {
      async.eachSeries(allRoles, function (role, asyncDone) {
        return deleteRole(role, asyncDone);
      }, function (err) {
        done(err);
      });
    },
    function __addAllPredefinedRole(done) {
      async.eachSeries(allRoles, function (role, asyncDone) {
        return createRole(role, asyncDone);
      }, function (err) {
        done(err);
      });
    }
  ],
  function (err) {
    logger.info('[acl/updateAllRoles] done / err=', err);
    return cb(err);
  });
}

function compareWithPrimaryRole(userId, targetRole, comparedMethod, cb) {
  getPrimaryRole(userId, function (err, primaryRole) {
    if(err) {
      return cb(err);
    }

    compareRoleLevel(primaryRole, targetRole, comparedMethod, function (err, resultOfMethod) {
      if(err) {
        return cb(err);
      }

      return cb(null, resultOfMethod);
    });
  });
}

//Note: support for new function (deafult role) instead migraion
function addDefaultRoleInsteadMigration(userId, cb) {
  hasTargetRole(userId, DEFAULT_ROLE, function (err, hasRole) {
    if(err) { return cb(err); }

    if(hasRole) {
      return cb();
    }

    addRoleToUser(userId, DEFAULT_ROLE, cb);
  });
}

//Note: support for new function (users/:id resource) instead migraion
function addUserOwnResourceInsteadMigration(userId, cb) {
  async.waterfall([
    function (done) {
      compareWithPrimaryRole(userId, SITE_ADMIN_DEFAULT_ROLE, COMPARED_METHOD.GREATER_OR_EQUAL, done);
    },
    function (isGreateOrEqual, done) {
      var userDefaultRole = getUserDefaultRoleId(userId);
      var userSelfResource = '/api/users/' + userId;

      if(isGreateOrEqual) {
        //Note: admin role don't need self permission. only endUser need users/:ownId permission
        acl.removeAllow(userDefaultRole, userSelfResource, ['r', 'u'], function () {

          return done();
        });
      } else {
        acl.allow(userDefaultRole, userSelfResource, ['r', 'u'], function (err) {
          if (err) {
            return DWError.newLibraryError({
              lib: 'acl', methodName: 'allow', userId: userId, resource: userSelfResource
            }, err, done);
          }

          return done();
        });
      }
    }
  ], function () {
    //Note: ignore err
    return cb();
  });
}

/**
 * get all role of target user. And find primary Role;
 *
 * @param {string} userId
 * @param cb
 */
function getPrimaryRole(userId, cb) {
  var userDefaultRole = getUserDefaultRoleId(userId),
      primaryRole = null;

  //Note: role_cfg가 변경시 고려 필요
  getUsersRoles(userId, function (err, userRoles) {
    if(err) {
      return cb(err);
    }

    //Note: union() For Default Role (user:*)
    primaryRole = _.find(_.union(PREDEFINED_ROLE, [userDefaultRole]), function (role) {
      return _.includes(userRoles, role);
    });

    return cb(null, primaryRole);
  });
}

/**
 * Get resources of target Role. and convert {id: '', perms: []} format
 * And filtering by collection Name on resources.
 * return converted format resources
 *
 * @param {string} roleId - target Role ID
 * @param {string|null} collectionName - (option) filtering collection Name
 * @param {function(err: object, result: array)} cb -
 */
function retrieveResources(roleId, collectionName, cb) {
  acl.whatResources(roleId, function (err, resourcesOfTargetRole) {
    if (err) {
      return DWError.newLibraryError({lib: 'acl', methodName: 'retrieveResources'}, err, cb);
    }

    var resources = [];
    _.forOwn(resourcesOfTargetRole, function (perms, id) {
      if (collectionName) {
        if(collectionName === (id && id.split('/')[2])) {
          resources.push({id: id, perms: perms});
        }
      } else {
        resources.push({id: id, perms: perms});
      }
    });

    return cb(null, resources);
  });
}

function isAllowedWithChildPermission(userId, resource, permission, callback) {
  var schema;

  async.waterfall([
    function __doValidation(done) {
      //Note: user can access owner resource with out acl permission when only 'read' method(r permission)
      if(permission !== 'r') {
        return DWError.newInvalidInput({message: 'permission only possible [r]'}, done);
      }

      // resource: (0)/api(1)/resourceCollectionName(2)/itemId(3)/xxxx(4)
      var ownerCollectionName= resource.split('/')[2];
      schema = _.find(DB_CFG, {collection: ownerCollectionName});
      var aclAllowReadWithChildPermission = schema && schema.authorization && schema.authorization.acl &&
          schema.authorization.acl.isAllowReadWithChildPermission;

      if(!schema || !aclAllowReadWithChildPermission) {
        return DWError.newInvalidInput({message: 'schema.aclAllowReadWithChildPermission must [true]'}, done);
      }

      return done();
    },
    function __getUserDefaultRole(done) {
      //Note: enduser에게만 현재 의미가 있음
      var userDefaultRole = getUserDefaultRoleId(userId);

      return done(null, userDefaultRole);
    },
    function __retrieveResources(userDefaultRole, done) {
      retrieveResources(userDefaultRole, schema.collection, done);
    },
    function __checkPermission(resourcesOfCollection, done) {
      var targetResourceInfo = _.find(resourcesOfCollection, function (resourceOfCollection) {
        if (_.includes(resourceOfCollection.id, resource)) {
          if (_.includes(resourceOfCollection.perms, permission) || _.includes(resourceOfCollection.perms, PERMISSION_ALL)) {
            logger.debug('[isAllowedWithChildPermission] resource, resourceOfCollection.id, resourceOfCollection.perms',
                resource, resourceOfCollection.id, resourceOfCollection.perms);
            return true;
          }
        }

        return false;
      });

      if(!targetResourceInfo) {
        return DWError.newNotFound({message: 'check permission deny', requestResource: resource}, done);
      }

      return done(null, targetResourceInfo);
    }
  ], function (err, targetResource) {
    //Note: err is mean false
    if(targetResource) {
      var aclResource = commonUtils.getACLResource(schema);
      var item = commonUtils.reverseTemplate(aclResource, targetResource.id);

      if(_.size(item) > 0) {
        return callback(null, true, targetResource);
      } else {
        return callback(null, true);
      }
    } else {
      return callback(null, false);
    }
  });
}

function isAllowedOfUserDefaultRole(userId, resource, permission, cb) {
  logger.debug('[isAllowedOfUserDefaultRole] resource: ', resource, ', permission: ', permission);

  if(!userId || !resource || !permission) {
    return cb(null, false);
  }

  async.waterfall([
    function (done) {
      var splitResources = getSplitResources(resource);

      return done(null, splitResources);
    },
    function (splitResources, done) {
      var userDefaultRole = getUserDefaultRoleId(userId);

      //Note: need migaration at async v2 (detectSeries result is chanced)
      async.detectSeries(splitResources, function (_resource, asyncDone) {
        acl.areAnyRolesAllowed(userDefaultRole, _resource, permission, function (err, isAllowed) {
          if (err) {
            return asyncDone(false);
          }

          return asyncDone(isAllowed);
        });
      }, function (detectedResource) {
        return done(null, detectedResource);
      });
    },
    function (detectedResource, done) {
      if(detectedResource || permission !== 'r') {
        return done(null, detectedResource);
      }

      isAllowedWithChildPermission(userId, resource, permission, done);
    }
  ], function (err, detectedResource) {
    var isAllow = detectedResource ? true : false;

    logger.debug('[isAllowedOfUserDefaultRole] isAllow: ', isAllow);
    return cb(null, isAllow);
  });
}
/**
 *
 * @param {string} userId -
 * @param {string} resource - API resource
 * @param {string} permission - c,r,u,d
 * @param cb(
 * @param {function(err:object, isAllowed:boolean, resource: )} cb - callback
 *
 */
function isAllowed(userId, resource, permission, cb) {
  function _doValidation(callback) {
    if(!userId) {
      return DWError.newInvalidInput({message: 'userId is required'}, callback);
    } else if(!resource) {
      return DWError.newInvalidInput({message: 'resource is required'}, callback);
    } else if(!permission) {
      return DWError.newInvalidInput({message: 'permission is required'}, callback);
    } else if(_.isArray(permission)) {
      return DWError.newInvalidInput({
        message: 'permission can not be array',
        permission: permission
      }, callback);
    }

    return callback();
  }
  
  function _getMatchedResourcesOnUserDefaultRole(userId, resource, callback) {
    var userDefaultRole = getUserDefaultRoleId(userId);

    // resource: (0)/api(1)/resourceCollectionName(2)/itemId(3)/xxxx(4)
    var ownerCollectionName = resource.split('/')[2];

    retrieveResources(userDefaultRole, ownerCollectionName, callback);
  }

  function _isAllowedOfAllUsersRole(userId, resource, permission, callback) {
    var resources = getSplitResources(resource);

    logger.debug('[isAllowed/start] userId, resource, permission, resources',
        userId, resource, permission, resources);

    async.waterfall([
      function (done) {
        //Note: need migaration at async v2 (detectSeries result is chanced)
        async.detectSeries(resources, function (_resource, asyncDone) {
          acl.isAllowed(userId, _resource, permission, function (err, isAllowed) {
            if (err) {
              logger.error('Error checking permissions to access resource');
              return asyncDone(false);
            }

            // logger.debug('[RS] _resource , ', _resource);
            // logger.debug('[RS] permission , ', permission);
            // logger.debug('[RS] isAllowed , ', isAllowed);

            return asyncDone(isAllowed);
          });
        }, function (detectedResource) {
          return done(null, detectedResource);
        });
      },
      function (detectedResource, done) {
        if(detectedResource) {
          return done(null, true);
        } else {
          return done(null, false);
        }
      }
    ], function (err, isAllowedResources) {
      //Note: ignore err
      logger.debug('[isAllowed/finish] isAllowedResources ', isAllowedResources);

      return callback(null, isAllowedResources);
    });
  }

  function _isAllowed() {
    async.waterfall([
      function (done) {
        _doValidation(done);
      },
      function (done) {
        addDefaultRoleInsteadMigration(userId, done);
      },
      function (done) {
        addUserOwnResourceInsteadMigration(userId, done);
      },
      function (done) {
        _getMatchedResourcesOnUserDefaultRole(userId, resource, done);
      },
      function __checkPermission(matchedResources, done) {
        logger.debug('[RS] matchedResources ', matchedResources);

        if(matchedResources && _.size(matchedResources) > 0) {
          return isAllowedOfUserDefaultRole(userId, resource, permission, done);
        } else {
          return _isAllowedOfAllUsersRole(userId, resource, permission, done);
        }
      }
    ], function (err, isAllowed) {
      //Note: ignore err
      return cb(null, isAllowed);
    });
  }

  return _isAllowed();
}

function resetEndUserRole(userId, cb) {
  var roleId = getUserDefaultRoleId(userId);

  async.waterfall([
    function __removeTargetRolesOnUser(done) {
      removeRoleOfUser(userId, roleId, done);
    },
    function __removeTargetRole(done) {
      deleteRole(roleId, done);
    },
    function __addNewRole(done) {
      createRole(roleId, done);
    },
    function __addUserRoles(done) {
      return addRoleToUser(userId, roleId, done);
    }
  ], function (err) {
    if(err) {
      return cb(err);
    }

    return cb();
  });
}


/*****************************************************************
 외부에서만 호출되는 method는 export에 직접
 내부에서도 호출될 수 있는 method는 function을 만들고 할당

******************************************************************/

module.exports.hasSystemAdminRole = function () {
  return function (req, res, next) {
    var loginUserId = authenticator.getLoggedinUserId(req.session);

    getPrimaryRole(loginUserId, function (err, primaryRole) {
      if(err) {
        return res.dwSendErr(err);
      }

      if(primaryRole && primaryRole.toLowerCase() === SYSTEM_ADMIN_DEFAULT_ROLE.toLowerCase()) {
        return next();
      } else {
        return DWError.newAclDeny({
          message: 'Only allow to SystemAdmin',
          userId: loginUserId
        }, res.dwSendErr);
      }
    });
  };
};

module.exports.middleware = function () {
  return function(req, res, next) {
    var opt = req.query || {},
        userId = authenticator.getLoggedinUserId(req.session),
        gatewayId = req.gateway && req.gateway.id,
        permission = PERMISSION_MAP[req.method.toLowerCase()],
        url = req.url.split('?')[0];

    url = decodeURIComponent(url);

    function _doBeforeMiddleware() {
      if (opt._profileInfo) {
        logger.info('Profile', opt._profileInfo.id, 'acl:middleware:start', (Date.now() - opt._profileInfo.startTime) / 1000);
      }

      delete req.query.isAllowedACL;
      delete req.query.auth;
    }

    function _doMiddlewareByGatewayId() {
      if (!_.startsWith(url, '/api/gateways/' + gatewayId)) {
        if (opt._profileInfo) {
          logger.info('Profile', opt._profileInfo.id, 'acl:middleware:end:gateway:401', (Date.now() - opt._profileInfo.startTime) / 1000);
        }

        return DWError.newAclDeny({
          message: 'Your Request is not allowed.',
          gatewayId: gatewayId,
          url: url
        }, res.dwSendErr);
      }

      applib.retrieveItemInternal(gatewayId, 'gateway', null, function(err, gateway) {
        if (err) {
          logger.error('acl.middleware() request from gateway / retrive gateway fail. gatewayId =',
              gatewayId,  'url=', url, 'err =', err);
          if (opt._profileInfo) {
            logger.info('Profile', opt._profileInfo.id, 'acl:middleware:end:gateway:404', (Date.now() - opt._profileInfo.startTime) / 1000);
          }

          return res.dwSendErr(err);
        }

        req.query.auth = authenticator.createAuthForGateway(gatewayId, gateway._service, gateway._service, gateway._site, gateway._site);
        req.query.isAllowedACL = true;

        if (opt._profileInfo) {
          logger.info('Profile', opt._profileInfo.id, 'acl:middleware:end:gateway', (Date.now() - opt._profileInfo.startTime) / 1000);
        }

        return next();
      });
    }

    function _doMiddlewareByUserId() {
      logger.debug('[middleware] userId, url, permission', userId, url, permission);

      if (opt._profileInfo) {
        logger.info('Profile', opt._profileInfo.id, 'acl:middleware:isAllowed', (Date.now() - opt._profileInfo.startTime) / 1000);
      }

      isAllowed(userId, url, permission, function (err, allowed) {
        logger.debug('[middleware] Done, ', allowed);

        if(err) {
          return res.dwSendErr(err);
        }

        if(!allowed) {
          return DWError.newAclDeny({
            message: 'Your Request is not allowed.',
            userId: userId,
            url: url,
            permission: permission
          }, res.dwSendErr);
        }

        if (allowed) {
          req.query.isAllowedACL = true;

          if (opt._profileInfo) {
            logger.info('Profile', opt._profileInfo.id, 'acl:middleware:end', (Date.now() - opt._profileInfo.startTime) / 1000);
          }

          return next();
        }
      });
    }
    
    function _middleware() {
      if (!permission) {
        return DWError.newInvalidInput({
          message: 'Use unidentified Method',
          method: req.method
        }, res.dwSendErr);
      }

      // _checkNeedMiddleware();

      _doBeforeMiddleware();

      // Access from GATEWAY!
      if(gatewayId) {
        return _doMiddlewareByGatewayId();
      } else if(userId) {
        return _doMiddlewareByUserId();
      } else {
        return DWError.newNeedLogin({
          message: 'You need login'
        }, res.dwSendErr);
      }
    }
    
    return _middleware();
  };
};

/**
 * only use when after retriveItem for ACL check
 *
 * @param item
 * @param dbType
 * @param opt
 * @param cb
 * @returns {*}
 */
module.exports.isAllowedByItem = function (item, dbType, permission, opt, cb) {
  var schema = DB_CFG[dbType];
  var auth = opt && opt.auth;
  var aclResource = commonUtils.getACLResource(schema);

  if(!schema) {
    return DWError.newInvalidInput({message: 'schema required'}, cb);
  } else if(!_.isObject(item) || _.isEmpty(item)) {
    return DWError.newInvalidInput({message: 'item must object. Item can\'t empty'}, cb);
  } else if(!permission) {
    return DWError.newInvalidInput({message: 'permission required'}, cb);
  }

  if(!opt) {
    //Note: auth가 없는 케이스가 삭제되면 해당 if문은 제거 필요
    return cb(null, true);
  } else if(opt.isAllowedACL) {
    //Note: already allowed by ACL middleware
    return cb(null, true);
  } else if (auth && auth.gateway) {
    //Note: From Gateway with out middleware
    if(dbType === 'sensor' || dbType === 'device' ) {
      return cb(null, _.isEqual(item.owner, auth.gateway));
    } else if(dbType === 'gateway') {
      return cb(null, _.isEqual(item.id, auth.gateway));
    } else {
      return cb(null, false);
    }
  } else if(!aclResource) {
    //Note: If schema haven't aclResource, Item is considered an item what don't need ACL check
    return cb(null, true);
  }

  var resource = template(aclResource, item);

  if (!resource) {
    //Note: item isn't enough make resource
    logger.info('[acl/isAllowedByItem] DENIED not enough info, id=', item.id, 'aclResource=', aclResource);
    return cb(null, false);
  } else if(!auth || !auth.user) {
    return cb(null, false);
  }

  isAllowed(auth.user, resource, permission, function (err, allowed) {
    if(err) {
      return cb(null, false);
    }

    return cb(null, allowed);
  });
};

module.exports.getAllMyResources= function (userId, cb) {
  logger.debug('[acl/getAllMyResources]', userId);

  async.waterfall([
    function (done) {
      addDefaultRoleInsteadMigration(userId, done);
    },
    function (done) {
      addUserOwnResourceInsteadMigration(userId, done);
    },
    function __getRoles(done) {
      getUsersRoles(userId, function (err, roles) {
        return done(err, roles);
      });
    },
    function __getAllResources(roles, done) {
      var roleWithResources = [];

      async.eachSeries(roles, function (role, asyncDone) {
        retrieveResources(role, null, function (err, resourcesOfTargetRole) {
          roleWithResources.push({id: role, resources: resourcesOfTargetRole});

          return asyncDone(err);
        });
      }, function (err) {
        return done(err, roleWithResources);
      });
    }
  ], function (err, result) {
    return cb(err, result);
  });
};

module.exports.getResourcesOfTargetRole = function (userId, roleId, cb) {
  async.waterfall([
    function __checkAcceptable(done) {
      compareWithPrimaryRole(userId, roleId, COMPARED_METHOD.GREATER_OR_EQUAL, function (err, isGreaterOrEqual) {
        if(err) {
          return done(err);
        }

        if(!isGreaterOrEqual) {
          return DWError.newAclDeny({
            message: 'You can\'t access target role',
            roleId: roleId
          }, done);
        }

        return done();
      });
    },
    function (done) {
      if(!isEndUserRole(roleId)) {
        return done();
      }

      var targetUserId = roleId.split(':')[1];

      return addUserOwnResourceInsteadMigration(targetUserId, done);
    },
    function __retrieveResources(done) {
      retrieveResources(roleId, null, function (err, resourcesOfTargetRole) {
        if (err) {
          return done(err);
        }

        return done(null, resourcesOfTargetRole);
      });
    }
  ], function (err, resourcesOfTargetRole) {
    return cb(err, resourcesOfTargetRole);
  });
};

module.exports.updateTargetRole = function (requestUserId, roleId, resources, cb) {
  var targetUserId = roleId.split(':')[1];

  async.waterfall([
    function __checkAcceptable(done) {
      compareWithPrimaryRole(requestUserId, SITE_ADMIN_DEFAULT_ROLE, COMPARED_METHOD.GREATER_OR_EQUAL, function (err, isGreaterOrEqual) {
        if(err) {
          return done(err);
        }

        if(!isGreaterOrEqual) {
          return DWError.newAclDeny({
            message: 'RequestUser must have role more than SiteAdmin.',
          }, done);
        }

        return done();
      });
    },
    function __removeTargetRolesOnUser(done) {
      removeRoleOfUser(targetUserId, roleId, done);
    },
    function __removeTargetRole(done) {
      deleteRole(roleId, done);
    },
    function __addNewRole(done) {
      var permissionsArray = [];
      var allows = [];

      _.forEach(resources, function (resource) {
        allows.push({
          resources: resource.id,
          permissions: resource.perms
        });
      });

      //Note: add user default role
      permissionsArray.push({
        roles: roleId,
        allows: _.union(allows, getUserDefaultRoleAllows(roleId))
      });

      return updateRole(permissionsArray, done);
    },
    function __addRoleToUser(done) {
      return addRoleToUser(targetUserId, roleId, done);
    }
  ], function (err) {
    return cb(err);
  });
};

/**
 * remove current roles on user. then remove user default role
 * called this method when after delete user on db
 *
 * @param {string} userId
 * @param cb
 */
module.exports.deleteUser = function (userId, cb) {
  var userDefaultRole = getUserDefaultRoleId(userId);

  async.waterfall([
    function __doValidation(done) {
      if(!userId) {
        return DWError.newInvalidInput({message: 'userId is required'}, done);
      }

      return done();
    },
    function __getRoles(done) {
      getUsersRoles(userId, done);
    },
    function __removeRolesToUser(roles, done) {
      logger.info('[acl/removeRoleToUser] userId=%s roles=%s', userId, roles);
      removeRoleOfUser(userId, roles, done);
    },
    function __deleteEndUserRole(done) {
      logger.info('[acl/deleteRole] role=%s', userDefaultRole);
      deleteRole(userDefaultRole, done);
    }
  ], function (err) {
    return cb && cb(err);
  });
};

/**
 * remove current roles, then replace new roles
 * If user default role has some permission, 'updateUser' don't reset user default role. Just update roles
 *
 * @param {string} userId
 * @param {string|array} newRoles
 * @param cb
 */
module.exports.updateUser = function (userId, newRoles, cb) {
  async.waterfall([
    function __doValidation(done) {
      if(!userId) {
        return DWError.newInvalidInput({message: 'userId is required'}, done);
      } else if(commonUtils.isUndefinedOrNull(newRoles)) {
        return DWError.newInvalidInput({message: 'roles is required. Even roles size is zero'}, done);
      }

      return done();
    },
    function __getRolesOfUser(done) {
      getUsersRoles(userId, done);
    },
    function __removeAllRoles(roles, done) {
      logger.info('[acl/updateUser] removeRole userId=%s roles=%s', userId, roles);
      removeRoleOfUser(userId, roles, done);
    },
    function __addNewRoles(done) {
      logger.info('[acl/updateUser] addRole userId=%s roles=%s', userId, newRoles);
      addRoleToUser(userId, newRoles, done);
    }
  ], function (err) {
    return cb && cb(err);
  });
};

/**
 * create user default role and add roles on user
 * called this method when after registered new User
 *
 * @param {string} userId
 * @param {string|array} roles
 * @param cb
 */
module.exports.createUser = function (userId, newRoles, cb) {
  async.waterfall([
    function __doValidation(done) {
      if(!userId) {
        return DWError.newInvalidInput({message: 'userId is required'}, done);
      } else if(_.size(newRoles) === 0) {
        return DWError.newInvalidInput({message: 'roles is required. And roles size more than one'}, done);
      }

      return done();
    },
    function __defaultRoleCheck(done) {
      retrieveResources(SYSTEM_ADMIN_DEFAULT_ROLE, null, done);
    },
    function __defaultRoleInit(resources, done) {
      if(!resources || _.size(resources) === 0) {
        return updateAllRoles(done);
      } else {
        return done();
      }
    },
    function __createUserDefaultRole(done) {
      var userDefaultRole = getUserDefaultRoleId(userId);
      createRole(userDefaultRole, done);
    },
    function __addRoleToUser(done) {
      addRoleToUser(userId, newRoles, done);
    }
  ], function (err) {
    if(err) {
      logger.error('[acl/createUser] err: ', err);
    }
    return cb && cb(err);
  });
};

module.exports.getAllowedResourceIdsOfUserDefaultRole = function (dbType, userId, cb) {
// ex) aclResource = /api/gateways/{id}   resourceId = /api/gateways/abcd/sensors/efg
  function getResourceId(aclResource, resourceId) {
    var result = commonUtils.reverseTemplate(aclResource, resourceId);

    if(!result) {
      return null;
    } else if(result['owner']) {
      return result['owner'];
    } else if(result['id']) {
      return result['id'];
    } else {
      return null;
    }
  }

  var schema = DB_CFG[dbType];

  async.waterfall([
    function __doValidation(done) {
      if (!userId) {
        return DWError.newInvalidInput({message: 'userId required.'}, done);
      }

      return done();
    },
    function __getUserDefaultRole(done) {
      var userDefaultRole = getUserDefaultRoleId(userId);
      return done(null, userDefaultRole);
    },
    function __retrieveResources(userDefaultRole, done) {
      retrieveResources(userDefaultRole, schema.collection, done);
    },
    function __getAllowedResourceIds(resourcesOfTargetRole, done) {
      var allowedResourceIds = [];
      var aclResource = commonUtils.getACLResource(schema);

      _.forEach(resourcesOfTargetRole, function (resource) {
        var resourceId;

        if (_.includes(resource.perms, 'r') || _.includes(resource.perms, PERMISSION_ALL)) {
          resourceId = getResourceId(aclResource, resource.id);

          if (resourceId) {
            if (!_.includes(allowedResourceIds, resourceId)) {
              allowedResourceIds.push(resourceId);
            }
          }
        }
      });

      return done(null, allowedResourceIds);
    }
  ], function (err, allowedResourceIds) {
    //Note: ignore error
    if (err) {
      allowedResourceIds = [];
    }

    return cb && cb(null, allowedResourceIds);
  });
};

module.exports.isAllowedOfUserDefaultRole = isAllowedOfUserDefaultRole;

module.exports.hasGreaterOrEqualRole = function (userId, targetRole, cb) {
  return compareWithPrimaryRole(userId, targetRole, COMPARED_METHOD.GREATER_OR_EQUAL, cb);
};

module.exports.hasGreaterRole = function (userId, targetRole, cb) {
  return compareWithPrimaryRole(userId, targetRole, COMPARED_METHOD.GREATER, cb);
};

module.exports.init = function (redisClient, cb) {
  if (redisClient) {
    var redisBackend = new Acl.redisBackend(redisClient, 'acl:');
    acl = new Acl(redisBackend, logger);
  } else {
    acl = new Acl(new Acl.memoryBackend());
  }

  return cb && cb();
};

module.exports.isEndUserRole = isEndUserRole;
module.exports.getRolesPolicy = getRolesPolicy;
module.exports.getUserDefaultRoles = getUserDefaultRoles;
module.exports.resetEndUserRole = resetEndUserRole;
module.exports.updateAllRoles = updateAllRoles;
module.exports.retrieveResources = retrieveResources;
module.exports.getPrimaryRole = getPrimaryRole;
module.exports.isAllowed = isAllowed;

// module.exports.PERMISSION_ALL = PERMISSION_ALL;
// module.exports.SYSTEM_ADMIN_DEFAULT_ROLE = SYSTEM_ADMIN_DEFAULT_ROLE;
module.exports.SERVICE_ADMIN_DEFAULT_ROLE = SERVICE_ADMIN_DEFAULT_ROLE;
module.exports.SITE_ADMIN_DEFAULT_ROLE = SITE_ADMIN_DEFAULT_ROLE;
module.exports.USER_DEFAULT_ROLE = USER_DEFAULT_ROLE;
// module.exports.DEFAULT_ROLE = DEFAULT_ROLE;
module.exports.USER_DEFAULT_ROLE_PREFIX = USER_DEFAULT_ROLE_PREFIX;

module.exports.forTest = {
  updateRole: updateRole
};