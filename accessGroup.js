'use strict';

var logger = require('log4js').getLogger('AUTHORIZATION'),
    _ = require('lodash');

var DB_CFG = require('../applib/db_cfg.json'),
    getAccessGroups = require('../utils').getAccessGroups,
    isUndefinedOrNull = require('../utils').isUndefinedOrNull;

var ASTERISK = '*';


function getAccessGroupByDBType(dbType, schemaDbGroups) {
  if(!schemaDbGroups) {
    var schema = DB_CFG[dbType];
    schemaDbGroups = getAccessGroups(schema);
  }

  return schemaDbGroups;
}

/**
 * Use for retrieve Item
 * Make deny when request user haven't accessgroup of item
 *
 * @param dbType
 * @param item
 * @param auth
 * @param schemaDbGroups
 * @returns {boolean}
 */
function checkDBGroup(dbType, item, auth, schemaDbGroups) {
  function isAllow(realValue, acceptValue, isSupportAsterisk) {
    return realValue === acceptValue ||
        acceptValue === ASTERISK ||
        isSupportAsterisk && realValue === ASTERISK;
  }

  schemaDbGroups = getAccessGroupByDBType(dbType, schemaDbGroups);

  if(!schemaDbGroups) {
    logger.debug('[accessGroup/checkDBGroup] dbType =', dbType, '. schemaDbGroups is not found');
    //Note: item is not need AccessGroupCheck when schemaDBGroup is null
    return true;
  }

  if(!item || !auth) {
    return false;
  }

  return _.every(schemaDbGroups, function (schemaDbGroup) {
    var accessFieldName = schemaDbGroup.key;
    var isSupportAsterisk = schemaDbGroup.asterisk;

    var realValue = item[accessFieldName];
    var acceptValue = auth[schemaDbGroup.target];

    logger.debug('[accessGroup/checkDBGroup] dbType =', dbType, ', accessFieldName =', accessFieldName, ', schemaDbGroup.target = ', schemaDbGroup.target,
        ', realValue =', realValue, 'acceptValue =', acceptValue, auth, item);

    if(!realValue || !acceptValue) {
      return false;
    }

    return isAllow(realValue, acceptValue, isSupportAsterisk);
  });
}

/**
 * Use for retrieve Collection
 * Make deny when user request unacceptable filter
 *
 * @param dbType
 * @param requestFilter
 * @param auth
 * @param schemaDbGroups
 * @returns {boolean}
 */
function isAvailableFilter(dbType, requestFilter, auth, schemaDbGroups) {
  schemaDbGroups = getAccessGroupByDBType(dbType, schemaDbGroups);

  if(!auth || !schemaDbGroups) {
    //Note: Skip when don't have auth or dbConfig.accessGroup
    return true;
  }

  //Note: Do not skip logic when filter's undefined. Handle undefined acceptValue even filter undefined
  return _.every(schemaDbGroups, function (schemaDbGroup) {
    var accessFieldName = schemaDbGroup.key;
    var acceptValue = auth[schemaDbGroup.target];

    if (!acceptValue) {
      return false; // exit every
    } else if (acceptValue !== ASTERISK && _.has(requestFilter, accessFieldName) && requestFilter[accessFieldName] !== acceptValue) {
      return false; // exit every
    }

    return true;
  });
}

/**
 * Use for retrieve Collection
 * Access All resources when Auth is null.
 * You have to set a isAllowedAccessGroup on option when you use doAuthorization for performance
 *
 * @param {string} dbType
 * @param {object} auth
 * @param {array} [schemaDbGroups]
 * @returns {object} filter -
 */
function getAccessGroupFilter(dbType, auth, schemaDbGroups) {
  var accessFilter = {}, filterList ;

  schemaDbGroups = getAccessGroupByDBType(dbType, schemaDbGroups);

  if(!schemaDbGroups || !auth) {
    return accessFilter;
  }

  _.forEach(schemaDbGroups, function (schemaDbGroup) {
    var accessFieldName = schemaDbGroup.key;
    var acceptValue = auth[schemaDbGroup.target];
    var isSupportAsterisk = schemaDbGroup.asterisk;

    if(isUndefinedOrNull(acceptValue)) {
      return true;
    }

    //Note: If accessFieldValue is '*', User can access All resources
    if (acceptValue !== ASTERISK) {
      if (isSupportAsterisk) {
        filterList = [acceptValue, ASTERISK];
      } else {
        filterList = [acceptValue];
      }

      accessFilter[accessFieldName] = filterList;
    }
  });

  return accessFilter;
}

module.exports = {
  checkDBGroup,
  isAvailableFilter,
  getAccessGroupFilter
};