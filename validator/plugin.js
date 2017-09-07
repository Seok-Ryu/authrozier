'use strict';

var _ = require('lodash');

var pluginMethods = {};



function createResult(isValid, err) {
  return {
    isValid: isValid,
    error: err
  }
}


pluginMethods.validateGatewayId = function (gatewayId) {
  function isIMEIValid(imei){
    if (!/^[0-9]{15}$/.test(imei)) {return false;}
    var sum = 0, factor = 2, checkDigit, multipliedDigit;
    for (var i = 13, li = 0; i >= li; i--) {
      multipliedDigit = parseInt(imei.charAt(i), 10) * factor;
      sum += (multipliedDigit >= 10 ? ((multipliedDigit % 10) + 1) : multipliedDigit);
      if (factor === 1) {
        factor++;
      } else {
        factor--;
      }
    }
    checkDigit = ((10 - (sum % 10)) % 10);
    return (checkDigit === parseInt(imei.charAt(14), 10));
  }

  //validate gateway Id - MAC or RFC4122 version 1/4 UUID
  var macRegex = /^([0-9A-F]{2}(:|-)?){5}([0-9A-F]{2})$/i,
    eui32Regex = /^([0-9A-F]{2}(:|-)?){3}([0-9A-F]{2})$/i,
    eui64Regex = /^([0-9A-F]{2}(:|-)?){7}([0-9A-F]{2})$/i,
    eui128Regex = /^([0-9A-F]{2}(:|-)?){15}([0-9A-F]{2})$/i,
    uuidRegex = /^([a-f\d]{8}(-?[a-f\d]{4}){3}-?[a-f\d]{12})$/i,
    oidRegex = /^[0-9\.]+(\.[0-9]+)$/,
    customRegex = /^[A-Za-z0-9]+_[A-Za-z0-9\.:_-]+$/i,
    validationResult;

  if (!gatewayId) {
    validationResult = createResult(false, {
      message: 'should have required property \'gatewayId\''
    });
  } else if (macRegex.test(gatewayId) === false &&
    eui32Regex.test(gatewayId) === false &&
    eui64Regex.test(gatewayId) === false &&
    eui128Regex.test(gatewayId) === false &&
    uuidRegex.test(gatewayId) === false &&
    oidRegex.test(gatewayId) === false &&
    customRegex.test(gatewayId) === false &&
    isIMEIValid(gatewayId) === false) {
    // logger.info('[validateGatewayId] invalid gateway id', gatewayId);
    validationResult = createResult(false, {
      gatewayId: gatewayId,
      message: 'invalid gateway id',
      plugInMethod: 'validateGatewayId'
    });
  } else {
    validationResult = createResult(true);
  }

  // console.log('[RS] valid gateway')

  return validationResult;
};

pluginMethods.fooooo = function () {

};



module.exports = pluginMethods;
