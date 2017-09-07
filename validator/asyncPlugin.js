'use strict';

var _ = require('lodash'),
    ajv = new require('ajv')(),
    async = require('async'),
    logger = require('log4js').getLogger('asyncPlugin');

var applib = require('../../common/applib'),
    DWError = require('../../common/response/error');

var asyncPluginMethods = {};


function createResult(isValid, err) {
  return {
    isValid: isValid,
    error: err
  };
}

asyncPluginMethods.fooooo = function () {
  /*validationResult = createResult(false, {
    gatewayId: gatewayId,
    message: 'invalid gateway id',
    plugInMethod: 'validateGatewayId'
  });*/
};

asyncPluginMethods.validateCustomField = function (req, res, next) {
  async.waterfall([
      function hasCustomField(done) {
        var method = req.method.toLowerCase(),
          customFields;

        if (method === 'post') {
          customFields = req.body.params && req.body.params.customFields;
        } else if (method === 'put') {
          customFields = req.body.customFields;
        } else {
          return done('skip');
        }

        if (!customFields) {
          logger.debug('[validateCustomField] No customFields');
          return done('skip');
        }

        done(null, customFields, method);
      },
      function getGatewayModelId(customFields, method, done) {
        if (method === 'post') {
          done(null, req.body.params && req.body.params.model, customFields);
        } else if (method === 'put') {
          applib.retrieveItemInternal(req.params.id, 'gateway', null, function (err, gateway) {
            if (err) {
              return done(err);
            } else {
              done(null, gateway.model, customFields);
            }
          });
        } else {
          return done('method must post or put');
        }
      },
      function retrieveGatewayModel(gatewayModelId, customFields, done) {
        applib.retrieveItemInternal(gatewayModelId, 'gatewayModel', null, function (err, gatewayModelItem) {
          if (err) {
            return done(err);
          } else {
            done(null, gatewayModelItem, customFields);
          }
        });
      },
      function validateCustomFields(gatewayModelItem, customFields, done) {
        var validationResult, isValid;

        if (_.isObject(gatewayModelItem.customFields)) {
          isValid = ajv.validate(gatewayModelItem.customFields, customFields);

          validationResult = createResult(isValid, _.first(ajv.errors));
        } else {
          validationResult = createResult(false, {
            plugInMethod: 'validateCustomField',
            gatewayModelId: gatewayModelItem.id,
            message: 'target GatewayModel can not use customField'
          });
        }

        done(null, validationResult);
      }
    ],
    function (err, validationResult) {
      if (err) {
        if (err === 'skip') {
          return next();
        } else {
          return res.dwSendErr(err);
        }
      } else if (validationResult.isValid) {
        return next();
      } else {
        return res.dwSendErr(DWError.create({
          code: DWError.ERROR_CODES.REQUEST_ERROR.SCHEMA_VALIDATE
        }, validationResult && validationResult.error));
      }
    });
};


module.exports = asyncPluginMethods;
