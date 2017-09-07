'use strict';

var _ = require('lodash'),
    logger = require('log4js').getLogger('ValidatorCore'),
    Ajv = require('ajv');

var VALIDATE_SCHEMA = require('../../common/schemas'),
    pluginMethodList = require('./plugin'),
    ajv = new Ajv();


function checkArguments(apiName, method, data) {
  if(_.isEmpty(apiName)) {
    logger.warn('[requestValidate] apiName is empty');
    throw new Error('apiName is empty');
    // return false;
  } else if(_.isEmpty(method)) {
    logger.warn('[requestValidate] method is empty');
    throw new Error('method is empty');
    // return false;
  } else if (_.isEmpty(data)) {
    logger.warn('[requestValidate] data is empty');
    //return false;
    return true;
  } else {
    return true;
  }
}

/**
 *
 * @param {boolean} isValid - result of validate
 * @param {object | string} [errorInfo] - error of validate
 * @returns {{isValid: boolean, [error: object]}}
 */
function createResult(isValid, errorInfo) {
  var result = {
    isValid: isValid
  };

  if(_.isString(errorInfo)) {
    result.error = {
      message: errorInfo
    };
  } else if(_.isObject(errorInfo) && !_.isNull(errorInfo)) {
    result.error = errorInfo;
  }

  return result;
}

function hasValidateDWSchema(schema) {
  return (!_.isUndefined(schema.dwValidateSchemas) && _.isArray(schema.dwValidateSchemas) && !_.isEmpty(schema.dwValidateSchemas));
}

function hasPluginMethods(schema) {
  return (!_.isUndefined(schema.dwPluginMethods) && _.isArray(schema.dwPluginMethods) && !_.isEmpty(schema.dwPluginMethods));
}

function isTemplatePath(path) {
  return (_.startsWith(path, '{{') && _.endsWith(path, '}}'));
}

function isFirstDepth(fieldName, separator) {
  //Note '.' is mean inside of data (ex: gateways.model, rule.trigger.method.over.degree)
  return _.indexOf(fieldName, separator) === -1;
}

/**
 *
 * @returns {string | null} resolved path
 */
function getResolvedPath(data, path, separator) {
  if(!data || _.isEmpty(data)) {
    return null;
  }

  var fieldName = path.slice(2, path.length - 2),
      resolvedPath;

  if(isFirstDepth(fieldName, separator)) {
    resolvedPath = data[fieldName];
  } else {
    // logger.info('[RS] fieldName, separator', fieldName, separator);
    resolvedPath = _.reduce(fieldName.split(separator), function (result, path) {
      return result[path];
    }, data);
  }

  return resolvedPath;
}

/**
 *
 * @param {object} rootItem - item is object. either schema or data
 * @param {array} paths - path(property name) list
 * @param {object} dataForResolvedPath - requsted data
 * @returns {object | null}
 */
function getItem(rootItem, paths, dataForResolvedPath, separator) {
  function _getItemByPath(item, path) {
    if(!item || !path) {
      return null;
    }

    if(item[path]) {
      return item[path];
    } else if(item.properties && item.properties[path]){
      return item.properties[path];
    } else {
      return null;
    }
  }

  function _getItem() {
    return _.reduce(paths, function (item, path) {
      var resolvedPath;

      if(_.size(path) === 0) {
        return item;
      }

      if(isTemplatePath(path)) {
        // logger.info('[RS] dataForResolvedPath ', dataForResolvedPath)
        // logger.info('[RS] before path // ', path);
        resolvedPath = getResolvedPath(dataForResolvedPath, path, separator);

        // logger.info('[RS] item, ' , item);
        // logger.info('[RS] after resolvedPath, ' , resolvedPath);

        return _getItemByPath(item, resolvedPath);
      } else {
        return _getItemByPath(item, path);
      }
    }, rootItem);
  }

  return _getItem();
}


/**
 *
 * @param rootSchema
 * @param targetPath
 * @param rootData
 * @returns {object | null} - target schema (or definition)
 */
function getTargetSchema(rootSchema, targetPath, rootData) {
  if(!rootSchema || !targetPath) {
    return null;
  } else if(!_.startsWith(targetPath, '#')) {
    //Note: schema path is must start '#'
    return null;
  }

  var paths = targetPath.slice(1).split('/'); //slice '#'

  return getItem(rootSchema, paths, rootData, '.');
}

/**
 *
 * @param rootData
 * @param targetPath
 * @returns {object} - data to need validation
 * @private
 */
function getTargetData(rootData, targetPath) {
  // logger.info("-----------------------:targetPath. ", targetPath);
  // logger.info("-----------------------:rootData. ", rootData);

  if(!rootData || !targetPath) {
    return null;
  } else if(!_.startsWith(targetPath, '@')) {
    //Note: data is must start '@'
    return null;
  }

  var paths = targetPath.slice(1).split('.'); //slice '@'

  return getItem(rootData, paths, rootData, '/');
}


/*
function getValidateTargetValue(inputData, fieldNamePath) {


  return _.reduce(fieldNamePath.split('.'), function (result, path) {
    var resolvedPath;

    if(isTemplatePath(path)) {
      resolvedPath = getResolvedPath(inputData, path);

      return result[resolvedPath];
    } else {
      return result[path];
    }
  }, inputData);
}*/

/**
 *
 * @param {object} rootSchema - schema what find in VALIDATE_SCHEMA by apiName & method
 * @param {object} rootData - data to need validation.
 * @returns {*}
 */
function doValidateDWSchema(rootSchema, rootData, method) {
  var ErrorOfSubSchemaValidation;
  
  function _checkDWExtend(targetSchema, _rootData) {
    var dwExtend = targetSchema && targetSchema.dwExtend,
        dataToNeedValidation,
        properties;

    if(_.isObject(dwExtend) && !_.isEmpty(dwExtend)) {
      dataToNeedValidation = getTargetData(_rootData, dwExtend.dataPath);
      properties = dwExtend.properties;

      if(_.isUndefined(dataToNeedValidation) || _.isNull(dataToNeedValidation)) {
        logger.info('[_checkDWExtend] validate data is null');
        return false;
      } else if(!_.isObject(properties) || _.isEmpty(properties)) {
        logger.info('[_checkDWExtend] dwExtend.properties is null');
        //TODO 개발자 실수.
        return false;
      } else {
        return true;
      }
    } else {
      logger.info('[_checkDWExtend] dwExtend is wrong');
      // logger.info('targetSchema', targetSchema)
      // logger.info('dwExtend', dwExtend);
      //TODO 개발자 실수.
      return false;
    }
    // return isValid;
  }

  function getResolvedSchemaPath(schemaPath, data, separator) {
    var paths = schemaPath.split('/');
    _.forEach(paths, function (path, index) {
      if(isTemplatePath(path)) {
        paths[index] = getResolvedPath(data, path, '.');
      }
    });

    return paths.join('/');
  }

  function _validate(data, validateMethod, schemaPath, fieldName, required) {
    var dwSchema, targetValue, isValid;

    dwSchema = getTargetSchema(VALIDATE_SCHEMA, schemaPath, data);
    targetValue = getTargetData(data, fieldName);

    // logger.info('[RS] validateMethod : ', validateMethod)
    // logger.info('[RS] schemaPath : ', schemaPath)
    // logger.info('[RS] targetValue : ', targetValue);

    if(!targetValue) {
      if(_.includes(required, fieldName)) {
        ErrorOfSubSchemaValidation = {
          extendRequired: required,
          fieldName: fieldName,
          value: targetValue
        };

        isValid = false;
        return isValid;
      } else {
        return true;
      }
    } else if(!dwSchema) {
      ErrorOfSubSchemaValidation = {
        extendRequired: required,
        value: targetValue
      };

      isValid = false;
      return isValid;
    }

    switch (validateMethod) {
      case 'oneOf':
        if(_.isObject(dwSchema) && !_.isArray(dwSchema)) {
          dwSchema = _.keys(dwSchema);
        }

        // logger.info('[RS] schema', dwSchema)
        isValid = _.includes(dwSchema, targetValue);
        // logger.info('result of oneOf: ', isValid);
        if(!isValid) {
          ErrorOfSubSchemaValidation = {
            validateMethod: validateMethod,
            schemaPath: getResolvedSchemaPath(schemaPath),
            data: data,
            fieldName: fieldName,
            value: targetValue,
            message: targetValue + ' is not available value in ' + fieldName
          };
        }

        break;
      case 'schema':
        if(!_.isObject(targetValue)) {
          isValid = false;

          ErrorOfSubSchemaValidation = {
            validateMethod: validateMethod,
            schemaPath: getResolvedSchemaPath(schemaPath),
            data: data,
            fieldName: fieldName,
            value: targetValue,
            message: 'data must be object. can not validate'
          };
        } else if(!_.isObject(dwSchema)) {
          //개발자 실수
          logger.warn('schema and value must object');
          isValid = true;
        } else {
          isValid = ajv.validate(dwSchema, targetValue);
          ErrorOfSubSchemaValidation = _.first(ajv.errors);
        }
        break;
      default:
        isValid = true;
        break;
    }//end of switch

    return isValid;
  }

  function _iterateValidate(dataToNeedValidation, validateMethod, schemaPath, fieldName, required) {
    if(_.isArray(dataToNeedValidation)) {
      return _.every(dataToNeedValidation, function (data) {
        return _iterateValidate(data, validateMethod, schemaPath, fieldName, required);
      });
    } else {
      return _validate(dataToNeedValidation, validateMethod, schemaPath, fieldName, required);
    }
  }

  function _validateDWExtend(dwExtend, _rootData) {
    var dataToNeedValidation = getTargetData(_rootData, dwExtend.dataPath),
        properties = dwExtend.properties,
        required = dwExtend.required,
        isValid;

    isValid = _.every(properties, function (validationInfo, fieldName) {
      var validateMethod, schemaPath, dwSchema, targetValue, isValid;

      if(!_.isObject(validationInfo) || _.isEmpty(validationInfo)) {
        //TODO 개발자 실수.
        logger.info('[_validateDWExtend] validationInfo is null');
        return true;
      }

      validateMethod = validationInfo.method;
      schemaPath = validationInfo.schemaPath;

      if(_.isArray(dataToNeedValidation)) {
        return _iterateValidate(dataToNeedValidation, validateMethod, schemaPath, fieldName, required);
      } else {
        return _validate(dataToNeedValidation, validateMethod, schemaPath, fieldName, required);
      }
    }); //end of every for properties

    logger.info('[_validateDWExtend] result isValid :', isValid);
    return isValid;
  }

  function _validateDWSchema() {
    var dwValidateSchemas = rootSchema.dwValidateSchemas, isValid;

    isValid = _.every(dwValidateSchemas, function (validateTargetInfo) {
      var targetSchema = getTargetSchema(rootSchema, validateTargetInfo.targetSchemaPath, rootData);

      if(_checkDWExtend(targetSchema, rootData)) {
        return _validateDWExtend(targetSchema.dwExtend, rootData); //stop every when _validate false
      }

      return true;
    }); //end of every

    return createResult(isValid, ErrorOfSubSchemaValidation);
  }

  return _validateDWSchema();
}

/**
 *
 * @param rootSchema
 * @param rootData
 * @returns {*}
 */
function doPluginMethod(rootSchema, rootData, method) {
  function _getMethodParam(paramInfo, data) {
    var methodParam;

    if(!paramInfo) {
      return null;
    }

    if(paramInfo.type === 'object') {
      methodParam = {};

      _.forEach(paramInfo.params, function (fieldPath, key) {
        methodParam[key] = getTargetData(data, fieldPath);
      });
    } else if(paramInfo.type === 'array') {
      methodParam = [];

      _.forEach(paramInfo.params, function (fieldPath) {
        methodParam.push(getTargetData(data, fieldPath));
      });
    } else {
      methodParam = getTargetData(data, paramInfo.params);
    }

    return methodParam;
  }

  function _doValidateMethod() {
    var dwPluginMethods = rootSchema.dwPluginMethods,
      validationResult = createResult(true);

    _.forEach(dwPluginMethods, function (methodInfo) {
      // console.log("[RS] methodInfo, ", methodInfo);

      var pluginMethod = pluginMethodList[methodInfo.methodName],
          paramInfo = methodInfo.paramInfo,
          methodParam;

      if(typeof pluginMethod !== 'function' || !paramInfo) {
        //Ryu 개발자 실수
        return true;
      }

      methodParam = _getMethodParam(paramInfo, rootData);

      if(_.isNull(methodParam) || _.isUndefined(methodParam)) {
        return true;
      }

      // console.log("[RS] methodParam, ", methodParam);

      validationResult = pluginMethod(methodParam);
      return validationResult.isValid;
    });

    return validationResult;
  }

  return _doValidateMethod();
}

function validateSchema(schema, data) {
  var isValid = ajv.validate(schema, data),
      error = _.first(ajv.errors);
  if(!isValid) {
    logger.info(schema);
  }

  return createResult(isValid, error);
}

function validateDWSchema(schema, data, method) {
  if(hasValidateDWSchema(schema)) {
    return doValidateDWSchema(schema, data, method);
  } else {
    return createResult(true);
  }
}

function validatePlugin(schema, data, method) {
  if(hasPluginMethods(schema)) {
    return doPluginMethod(schema, data, method);
  } else {
    return createResult(true);
  }
}

function doAllValidation(schema, data, method) {
  var methodList = [
    validateSchema, validateDWSchema, validatePlugin
  ], resultOfValidation;

  _.forEach(methodList, function (validationMethod) {
    resultOfValidation = validationMethod(schema, data, method);

    return resultOfValidation.isValid; //stop when valid is false
  });

  return resultOfValidation;
}

/**
 * schema validation
 *
 * @param {string} apiName - called api name. when api has '/', replace '-'
 * @param {string} method - http request method (post, put, get, del)
 * @param {object} data - data to need validation.
 * @return {{isValid: boolean, error: object}} result of validate
 *
 */
module.exports.requestValidate = function(apiName, method, data) {
  try {
    checkArguments(apiName, method, data);
  } catch (err) {
    return createResult(false, 'Fail checkArguments!' + err);
  }

  var schema = VALIDATE_SCHEMA[apiName] && VALIDATE_SCHEMA[apiName][method];

  //Ryu schema가 없으면 valid true, schema 생성완료뒤 코드 수정 필요. return valid false
  if(!schema) {
    logger.info('[requestValidate] SKIP schema is empty');
    return createResult(true, 'Can not Find Schema!');
    //return createResult(false, 'Can not Find Schema!');
  }

  logger.info('[requestValidate] apiName = %s , method = %s, schema title = %s ', apiName, method, schema.title);
  // logger.info('[RS]', JSON.stringify(schema, null, 2))

  return doAllValidation(schema, data, method);
};

/*

{
  "statusCode": 400,
  "message": "Bad Request",
  "errors":[
  {
    "code": "SCHEMA_VALIDATE",
    "detail":{
      "required":[
        "body.id"
      ]
    },
    "category": "REQUEST_ERROR",
    "statusCode": 400
  }
]
}

*/

/*

{
  "statusCode": 400,
  "message": "Bad Request",
  "errors":[
  {
    "code": "SCHEMA_VALIDATE",
    "message": "should have required property 'id'",
    "detail":{
      "keyword": "required",
      "dataPath": "",
      "schemaPath": "#/required",
      "params":{
        "missingProperty": "id"
      },
      "message": "should have required property 'id'"
    },
    "category": "REQUEST_ERROR",
    "statusCode": 400
  }
]
}

 /*
 ## SAMPLE ERROR ##

 { keyword: 'enum',
 dataPath: '.info.useRealtime',
 schemaPath: '#/properties/info/properties/useRealtime/enum',
 params: { allowedValues: [Object] },
 message: 'should be equal to one of the allowed values' }

 { keyword: 'required',
 dataPath: '',
 schemaPath: '#/required',
 params: { missingProperty: 'name' },
 message: 'should have required property \'name\'' }
 //Setting 가능한지 살펴볼것

 {
 "keyword": "required",
 "dataPath": "",
 "schemaPath": "#/required",
 "params":{
 "missingProperty": "id"
 },
 "message": "should have required property 'id'"
 }

 ajv.errors : [ { keyword: 'type',
 dataPath: '.trigger.filter.gateway',
 schemaPath: '#/properties/trigger/properties/filter/properties/gateway/type',
 params: { type: 'string' },
 message: 'should be string' } ]
 */
/*result.error = {
 key : _.findKey(errorInfo.params),
 params: errorInfo.params[_.findKey(errorInfo.params)],
 message: errorInfo.message
 }
 
 */
