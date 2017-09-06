/**
 * Created by RyuFirst on 2017. 7. 27..
 */

'use strict';

var logger = require('log4js').getLogger('AUTHORIZATION'),
    redis = require('redis'),
    Lru = require('lru-cache'),
    async = require('async'),
    _ = require('lodash');

var acl = require('./acl'),
    accessGroup = require('./accessGroup'),
    applib = require('../applib'),
    commonUtils = require('../utils'),
    DB_CFG = require('../applib/db_cfg.json'),
    DWError = require('../response/error');

var PUB_SUB_KEY = 'authorizer.cache';

var cache, rcSub, rcPub;

function resetCache() {
  if (rcPub) {
    rcPub.publish(PUB_SUB_KEY, '*');
  }

  cache.reset();
  logger.info('[authorizer] resetCache');
}

function removeCache(userId) {
  if(!userId) {
    return;
  }

  if (rcPub) {
    rcPub.publish(PUB_SUB_KEY, userId);
  }

  var allKeys = cache.keys();
  _.forEach(allKeys, function (cacheKey) {
    var cachedUserId = cacheKey.split('-')[0];

    if(cachedUserId === userId) {
      cache.del(cacheKey);
    }
  });

  logger.info('[authorizer] removeCache userId=%s', userId);
}

function getCacheKey(userId, dbType, id, permission) {
  if(!userId || !dbType || !id || !permission) {
    return null;
  }

  return [userId, dbType, id, permission].join('-');
}

function setCache(cacheKey, isAllowed, reason) {
  if(!cacheKey) {
    return;
  }

  cache.set(cacheKey, {
    isAllowed: isAllowed,
    reason: reason
  });
}

function findInCache(cacheKey) {
  if(!cacheKey) {
    return null;
  }

  var cachedData = cache.get(cacheKey);

  return cachedData;
}

function updateAllRoles(cb) {
  resetCache();
  acl.updateAllRoles(cb);
}

function resetEndUserRole(userId, cb) {
  removeCache(userId);
  acl.resetEndUserRole(userId, cb);
}

function updateTargetRole(requestUserId, roleId, resources, cb) {
  var targetUserId = roleId.split(':')[1];
  removeCache(targetUserId);
  acl.updateTargetRole(requestUserId, roleId, resources, cb);
}

function updateUser(userId, newRoles, cb) {
  removeCache(userId);
  acl.updateUser(userId, newRoles, cb);
}

/**
 * Check request Filter available and then make filter for db query when retrieve collection
 *
 * @param dbType
 * @param opt
 * @param cb(err, filter)
 */
function getQueryFilter(dbType, opt, cb) {
  var filter = opt && opt.filter || {};
  var auth = opt && opt.auth;
  var filters = [];

  logger.debug('[authorization/getQueryFilter] start dbType:, ', dbType, ', opt: ', opt);


  function _getQueryFilter() {
    async.waterfall([
      function __doValidation(done) {
        if(!dbType) {
          return DWError.newInvalidInput({message: 'dbType is required'}, done);
        }

        return done();
      },
      function __isAvailableFilter(done) {
        var isAvailableFilter = accessGroup.isAvailableFilter(dbType, filter , auth);

        if(!isAvailableFilter) {
          return DWError.newAccessgroupDeny({ dbType : dbType, auth: auth, filter: filter}, done);
        }

        return done();
      },
      function __getAllowedFilter(done) {
        acl.getAllowedResourceIdsOfUserDefaultRole(dbType, auth && auth.user, done);
      },
      function __setFilterWithAllowedResourceIds(allowedResourceIds, done) {
        var allowFilter;

        if (allowedResourceIds && _.size(allowedResourceIds) > 0) {
          allowFilter = _.cloneDeep(filter);

          if (_.isUndefined(allowFilter.id) ||_.isNull(allowFilter.id)) {
            allowFilter.id = allowedResourceIds;
          } else {
            allowFilter.id = _.isArray(allowFilter.id) ? allowFilter.id : [allowFilter.id];
            allowFilter.id = _.intersection(allowFilter.id, allowedResourceIds);
          }

          filters.push(allowFilter);
        }

        return done();
      },
      function __getAccessGroupFilter(done) {
        var availableAccessFilter = accessGroup.getAccessGroupFilter(dbType, auth);

        return done(null, availableAccessFilter);
      },
      function __mixedFilter(availableAccessFilter, done) {
        _.forOwn(availableAccessFilter, function(value, key) {
          //Note: override value if already exist
          filter[key] = value;
        });

        if (!_.isEmpty(filter)) {
          filters.push(filter);
        }

        return done();
      }
    ], function (err) {
      if(err) {
        logger.info('[authorization/getQueryFilter] error: ', err);
        return cb && cb(err);
      }

      logger.debug('[authorization/getQueryFilter] done filters: ', filters, ', dbType : ', dbType);
      return cb && cb(null, filters);
    });
  }

  return _getQueryFilter();
}

/**
 * check permission of item.
 *
 * @param item
 * @param dbType
 * @param permission
 * @param opt
 * @param cb
 */
function doAuthorizationByItem(item, dbType, permission, opt, cb) {
  function _needCheckACL(schema) {
    var checkList = schema.authorization && schema.authorization.checkList;
    return _.includes(checkList, 'acl');
  }

  function _needCheckAccessGroup(schema) {
    var checkList = schema.authorization && schema.authorization.checkList;
    return _.includes(checkList, 'accessGroup');
  }

  function _checkOwnerAccessGroup(ownerDbType, ownerId, auth, cb) {
    logger.debug('[authorization/_checkOwnerAccessGroup] start, dbType: %s, ownerId: %s', ownerDbType, ownerId);

    async.waterfall([
      function (done) {
        applib.retrieveItemInternal(ownerId, ownerDbType, null, done);
      },
      function (ownerItem, done) {
        var isAllowedAccessGroup = accessGroup.checkDBGroup(ownerDbType, ownerItem, opt.auth);

        logger.debug('[authorization/_checkOwnerAccessGroup] finish! isAllowedAccessGroup, ', isAllowedAccessGroup, ', ', ownerItem.id, opt.auth);

        if(!isAllowedAccessGroup) {
          return DWError.newAccessgroupDeny({
            message: 'Insufficient permissions',
            dbType: ownerDbType, itemId: ownerItem.id, auth: auth,
          }, done);
        }

        return done();
      }
    ], function (err) {
      return cb(err);
    });
  }

  var auth = opt && opt.auth;
  var schema = DB_CFG[dbType];
  logger.debug('[authorization/doAuthorizationByItem] start. itemId: ', item.id, ', dbType: ', dbType, ', permission: ', permission, ', auth: ', auth);

  if(!auth || !schema) {
    //FIXME: auth가 없는 경우를 만들지 말것. auth가 없는 경우를 모두 제거
    return cb && cb(null, true);
  }

  var cacheKey = getCacheKey(auth && auth.user, dbType, item && item.id, permission);
  var cachedData = findInCache(cacheKey);

  if(cachedData) {
    logger.debug('[authorization/doAuthorizationByItem] cachedData', cachedData);
    return cb && cb(cachedData.reason);
  }


  async.waterfall([
    function __doValidation(done) {
      if(_.isEmpty(item)) {
        return DWError.newInvalidInput({message: 'item is required'}, done);
      } else if (!permission) {
        return DWError.newInvalidInput({message: 'permission is required'}, done);
      }

      return done();
    },
    function __checkACL(done) {
      if(!_needCheckACL(schema)) {
        return done();
      }

      acl.isAllowedByItem(item, dbType, permission, opt, function (err, allowed) {
        if (err) {
          return done(err);
        } else if (!allowed) {
          return DWError.newAclDeny({
            message: 'Insufficient permissions',
            dbType: dbType, itemId: item.id, auth: auth, permission: permission
          }, done);
        }

        logger.debug('[authorization/doAuthorizationByItem] __checkACL [', permission, '] : ', allowed);

        return done();
      });
    },
    function __isAllowOfUserDefaultRole(done) {
      var aclResource = commonUtils.getACLResource(schema);
      var resource = commonUtils.template(aclResource, item);

      acl.isAllowedOfUserDefaultRole(auth && auth.user, resource, permission, done);
    },
    function __checkOwnerAccessGroup(isAllowedOfUserDefaultRole, done) {
      if(isAllowedOfUserDefaultRole || !item.owner) {
        return done(null, isAllowedOfUserDefaultRole);
      }

      //Note: IF the user has role more than SiteAdmin, He passes acl of any sensor, device, or gateway
      //And Sensor, device can't check AccessGroup. Therefore check accessGroup of owner
      _checkOwnerAccessGroup(schema.owner, item.owner, auth, function (err) {
        if(err) {
          return done(err);
        }

        return done(null, isAllowedOfUserDefaultRole);
      });
    },
    function __needCheckAccessGroup(isAllowedOfUserDefaultRole, done) {
      if(opt.isAllowedAccessGroup) {
        return done(null, false);
      } else if(!_needCheckAccessGroup(schema)) {
        return done(null, false);
      } else {
        //Note: If userDefault Role have permission (For MultiSite access)
        //Note: do not check accessGroup when isAllowed true
        return done(null, !isAllowedOfUserDefaultRole);
      }
    },
    function __checkAccessGroup(needCheckAccessGroup, done) {
      if(!needCheckAccessGroup) {
        logger.debug('[authorization/doAuthorizationByItem] skip check access group');
        //Note: skip access group check
        return done();
      }

      var isAllowedAccessGroup = accessGroup.checkDBGroup(dbType,item, opt.auth);

      // logger.debug('[item] ', item);
      logger.debug('[authorization/doAuthorizationByItem] __checkAccessGroup, ', isAllowedAccessGroup, ', ', item.id, opt.auth);

      if(!isAllowedAccessGroup) {
        return DWError.newAccessgroupDeny({
          message: 'Insufficient permissions',
          dbType: dbType, itemId: item.id, auth: auth,
        }, done);
      }

      return done();
    }
  ], function (err) {
    var cacheKey = getCacheKey(auth.user, dbType, item && item.id, permission);

    if(err) {
      logger.info('[authorization/doAuthorizationWithItem] error: ', err);
      setCache(cacheKey, false, err);
      return cb && cb(err);
    }

    logger.info('[authorization/doAuthorizationWithItem] Done without error');
    setCache(cacheKey, true);

    return cb && cb(null, true);
  });
}

/**
 * Check Item's authorization
 *
 * @param {string} id - item id
 * @param {string} dbType - item dbType
 * @param {string} permission - [r, u, d]
 * @param {object} auth -
 * @param {function} cb - err, item
 */
function doAuthorizationById(id, dbType, permission, auth, cb) {
  logger.debug('[authorization/doAuthorizationById] id: ', id, ', dbType: ', dbType, ', permission: ', permission, ', auth: ', auth);

  var cacheKey = getCacheKey(auth && auth.user, dbType, id, permission);
  var cachedData = findInCache(cacheKey);

  if(cachedData) {
    logger.debug('[authorization/doAuthorizationById] cachedData', cachedData);
    return cb && cb(cachedData.reason);
  }

  async.waterfall([
    function __retrieveItem(done) {
      //Fixme: applib make circulation
      applib.retrieveItemInternal(id, dbType, null, done);
    },
    function __checkAuthorization(item, done) {
      doAuthorizationByItem(item, dbType, permission, { auth: auth}, function (err) {
        if(err) {
          return done(err);
        }

        return done();
      });
    }
  ], function (err) {
    return cb && cb(err);
  });
}

function setRedisPubSub(isWritable, redisPubSub, cb) {
  if (!redisPubSub) {
    return cb && cb(new Error('setRedisPubSub / missing store'));
  }

  if (isWritable) {
    //to public
    rcPub = redisPubSub;
  } else {
    //to subscribe
    if (rcSub && rcSub.end) {
      rcSub.end();
    }

    rcSub = redis.createClient(redisPubSub.port, redisPubSub.host);

    if (redisPubSub.selected_db) {
      rcSub.select(redisPubSub.selected_db);
    }

    rcSub.once('subscribe', function (channel, count) {
      logger.info('channel [%s] is subscribed, count: %s', channel.toString(), count);
    });

    rcSub.on('message', function (channel, message) {
      if(channel === PUB_SUB_KEY) {
        if (message === '*') {
          resetCache();
        } else {
          removeCache(message);
        }
      }
    });

    rcSub.subscribe(PUB_SUB_KEY);
  }

  return cb && cb();
}

function init(redisClient, cb) {
  if (!cache) {
    cache = new Lru({ max: 10000, maxAge: 10 * 60 * 1000 }); //NOTE: save 10000 item, saving 10 minute
  }

  acl.init(redisClient, cb);
}

//Note: use this method when you need authorization
var publicExports = {
  doAuthorizationByItem: doAuthorizationByItem,
  doAuthorizationById: doAuthorizationById,
  getQueryFilter: getQueryFilter,
  middleware: acl.middleware,
  setRedisPubSub: setRedisPubSub,
  init: init,
};

//Note: use this method only special case
var privateExports = {
  isAllowedOfUserDefaultRole: acl.isAllowedOfUserDefaultRole,

  hasSystemAdminRole: acl.hasSystemAdminRole,
  hasGreaterRole: acl.hasGreaterRole,
  hasGreaterOrEqualRole: acl.hasGreaterOrEqualRole,
  isEndUserRole: acl.isEndUserRole,
  getRolesPolicy: acl.getRolesPolicy,
  getUserDefaultRoles: acl.getUserDefaultRoles,
  retrieveResources: acl.retrieveResources,
  getPrimaryRole: acl.getPrimaryRole,

  getAllMyResources: acl.getAllMyResources,
  getResourcesOfTargetRole: acl.getResourcesOfTargetRole,
  updateTargetRole: updateTargetRole,
  resetEndUserRole: resetEndUserRole,
  updateAllRoles: updateAllRoles,
  deleteUser: acl.deleteUser,
  updateUser: updateUser,
  createUser: acl.createUser,

  SERVICE_ADMIN_DEFAULT_ROLE: acl.SERVICE_ADMIN_DEFAULT_ROLE,
  SITE_ADMIN_DEFAULT_ROLE: acl.SITE_ADMIN_DEFAULT_ROLE,
  USER_DEFAULT_ROLE: acl.USER_DEFAULT_ROLE,
  USER_DEFAULT_ROLE_PREFIX: acl.USER_DEFAULT_ROLE_PREFIX,
};

module.exports = _.merge(publicExports, privateExports);