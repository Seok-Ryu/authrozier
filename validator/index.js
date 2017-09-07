'use strict';

var _ = require('lodash'),
    logger = require('log4js').getLogger('ValidatorWrapper');

var core = require('./core.js'),
    DWError = require('../../common/response/error'),
    logShipper = require('../../common/logShipper');

var ALLOW_API_SCHEMAS = [
  'gateways-sensors-status', 'widgets', 'rules',
  'registerGateway', 'controlActuator', 'registerGatewayKey', 'activateGatewayKey', 'manageGateway', 'changePassword', 'users', 'users/me',
  'pushDevices', /*'gatewayModels',*/ 'oauth2-authClients', 'oauth2-authorize', 'oauth2-token', 'gateways-sensors-series',
  'gateways-status', 'gateways', 'gateways-sensors', 'gateways-devices'
];
var NO_PARAM_APIS = ['oauth2'];

var EXCEPTION_WORDS = {
  'post': ['ctime', 'mtime', 'owner', 'series'], //status는 다른곳에서 많이 써서 방법이...
  'put': ['reqId']
};

var ALLOW_API_SCHEMAS_LOWER = _.map(ALLOW_API_SCHEMAS, function (name) {
  return name.toLowerCase();
});

function isAllowSchema(apiName) {
  return _.includes(ALLOW_API_SCHEMAS, apiName);
}

function sendLogShipper(info, auth) {
  if (auth && auth.loggedinUser) {
    info.serviceId = auth.loggedinUser.service;
    info.siteId = auth.loggedinUser.site;
    info.userId = auth.loggedinUser.id;
  }

  logShipper.info(info, {category: 'ShipperValidator'});
}

function doValidate() {
  return function (req, res, next) {
    /**
     * path: '/gateways/777f869932564e4aa6b937a2a7f9cc2e/sensors' => 'gateways-sensors'
     * path: '/api/gateways/777f869932564e4aa6b937a2a7f9cc2e/sensors' => 'gateways-sensors'
     * path: '/api/registerGateway' => 'registerGateway'
     * path: '/api/oauth2/token' => 'oauth2-token'  // NO_PARAM_APIS
     */
    function getAPIName(path) {
      var apiNames, apiPath = path.replace(/^\/api\//, '').split('/');

      // path: '/registerGateway' => apiPath: ['', 'registerGateway']
      if (!apiPath[0]) {
        apiPath = apiPath.slice(1);
      }

      if (_.includes(NO_PARAM_APIS, apiPath[0])) {
        return apiPath.join('-');
      }

      apiNames = _.filter(apiPath, function (path, idx) {
        return path && (idx % 2) === 0;
      });

      var apiName = apiNames.join('-');
      var index = ALLOW_API_SCHEMAS_LOWER.indexOf(apiName.toLowerCase());
      return ALLOW_API_SCHEMAS[index] || apiName;
    }

    function getAPIParams(path) {
      var apiParams, apiPath = path.replace(/^\/api\//, '').split('/');
      if (!apiPath[0]) {
        apiPath = apiPath.slice(1);
      }

      if (_.includes(NO_PARAM_APIS, apiPath[0])) {
        return [];
      }

      apiParams = _.filter(apiPath, function (path, idx) {
        return path && (idx % 2) === 1;
      });

      return apiParams;
    }

    function _hasExceptionBody(method, body) {
      var keys = _.keys(body), result = false;

      _.forEach(EXCEPTION_WORDS[method], function (exceptionword) {
        result = _.includes(keys, exceptionword);

        return !result; //Stop forEach when result true
      });

      return result;
    }

    function _removeExceptionBody(method, body) {
      var keys = _.keys(body);

      _.forEach(EXCEPTION_WORDS[method], function (exceptionword) {
        if(_.includes(keys, exceptionword)) {
          delete body[exceptionword];
        }
      });
    }

    function _doValidate() {
      var method, body, params, query, path, apiName, url, customParam;
      var schemaError, errorMsg;

      method = req.method.toLowerCase();
      body = req.body;
      params = req.params;
      query = req.query;
      path = req.path;    //  '/widgets/14'
      url = req.url;
      apiName = getAPIName(path);
      customParam = getAPIParams(path);

      // logger.info('[RS] req.headers' , req.headers);
      logger.info('[RS] req.body' , JSON.stringify(body, null, 2));
      logger.info('[RS] req.method' , method);
      logger.info('[RS] req.path' , path);
      logger.info('[RS] req.url' , url);
      // logger.info('[RS] req.query' , query);
      // logger.info('[RS] req.params' , params);



      //TODo isAllowSchema will be remove when all schema validate ready.
      if (method === 'get') {
        return next();
      } else if (method === 'delete') {
        if (_.size(customParam) > 0) {
          return next();
        } else {
          return res.dwSend({
            error: DWError.create({
              code: DWError.ERROR_CODES.REQUEST_ERROR.SCHEMA_VALIDATE,
              message: 'require delete target id'
            })
          });
        }
      } else if (!isAllowSchema(apiName)) {
        logger.info('[doValidate] SKIP schema validate');
        return next();
      }

      /*
        Note: some gateway or 3rd party use api with unnecessarily parameter
        So defined exception word list, and make log when they use it.
        and notify to them to fix it.
      */
      if(_hasExceptionBody(method, body)) {
        sendLogShipper({
          logType: 'validator',
          apiName: apiName,
          method: method,
          body: body,
          error: 'warning'
        }, req.session && req.session.auth);
        _removeExceptionBody(method, body);
      } else if(apiName === 'registerGateway') {
        //Note : registerGateway use 'id' in v1, but no more support 'id' in v2.
        if(body.id) {
          sendLogShipper({
            logType: 'validator',
            apiName: apiName,
            method: method,
            body: body,
            error: 'warning'
          }, req.session && req.session.auth);

          body.reqId = body.id;
          delete body.id;
        }
      }

      var validationResult = core.requestValidate(apiName, method, body);

      if (validationResult && validationResult.isValid) {
        // logger.info('[RS] Validation Success');
        return next();
      }

      schemaError = validationResult && validationResult.error;
      //TODO Ryu warn -> debug
      logger.warn('[doValidate] validate Fail cause ', schemaError && schemaError.message);

      try {
        errorMsg = JSON.stringify(schemaError);
      } catch (e) {
        errorMsg = schemaError;
      }

      sendLogShipper({
        logType: 'validator',
        apiName: apiName,
        method: method,
        body: body,
        error: errorMsg
      }, req.session && req.session.auth);

      return DWError.newSchemaValidate({message: schemaError && schemaError.message}, schemaError, res.dwSendErr);
    }

    return _doValidate();
  };
}

module.exports = {
  apis: doValidate
};
