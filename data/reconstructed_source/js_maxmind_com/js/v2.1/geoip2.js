/* eslint-disable */
window.geoip2 = (function () {
  'use strict';
  var exports = {};

  function Lookup(successCallback, errorCallback, options, type) {
    this.successCallback = successCallback;
    this.errorCallback = errorCallback;
    this.type = type;
  }

  Lookup.prototype.returnSuccess = function (location) {
    if (this.successCallback && typeof this.successCallback === 'function') {
      this.successCallback(this.fillInObject(JSON.parse(location)));
    }
  };

  Lookup.prototype.returnError = function (error) {
    if (this.errorCallback && typeof this.errorCallback === 'function') {
      if (!error) {
        error = {
          error: 'Unknown error'
        };
      }
      this.errorCallback(error);
    }
  };

  var fillIns = {
    country: [
      ['continent', 'Object', 'names', 'Object'],
      ['country', 'Object', 'names', 'Object'],
      ['registered_country', 'Object', 'names', 'Object'],
      ['represented_country', 'Object', 'names', 'Object'],
      ['traits', 'Object']
    ],
    city: [
      ['city', 'Object', 'names', 'Object'],
      ['continent', 'Object', 'names', 'Object'],
      ['country', 'Object', 'names', 'Object'],
      ['location', 'Object'],
      ['postal', 'Object'],
      ['registered_country', 'Object', 'names', 'Object'],
      ['represented_country', 'Object', 'names', 'Object'],
      ['subdivisions', 'Array', 0, 'Object', 'names', 'Object'],
      ['traits', 'Object']
    ]
  };
  Lookup.prototype.fillInObject = function (obj) {
    var fill = this.type === 'country' ? fillIns.country : fillIns.city;

    for (var i = 0; i < fill.length; i++) {
      var path = fill[i];
      var o = obj;

      for (var j = 0; j < path.length; j += 2) {
        var key = path[j];
        if (!o[key]) {
          o[key] = path[j + 1] === 'Object' ? {} : [];
        }
        o = o[key];
      }
    }

    try {
      Object.defineProperty(obj.continent, 'continent_code', {
        enumerable: false,
        get: function () {
          return this.code;
        },
        set: function (value) {
          this.code = value;
        }
      });
    } catch (e) {
      if (obj.continent.code) {
        obj.continent.continent_code = obj.continent.code;
      }
    }

    if (this.type !== 'country') {
      try {
        Object.defineProperty(obj, 'most_specific_subdivision', {
          enumerable: false,
          get: function () {
            return this.subdivisions[this.subdivisions.length - 1];
          },
          set: function (value) {
            this.subdivisions[this.subdivisions.length - 1] = value;
          }
        });
      } catch (e) {
        obj.most_specific_subdivision =
          obj.subdivisions[obj.subdivisions.length - 1];
      }
    }

    return obj;
  };

  Lookup.prototype.getGeoIPResult = function () {
    var targetHostname;
    var hostname = window.location.hostname;
    var revHostnameSplit = hostname.split('.').reverse();
    if (
      revHostnameSplit[1] === 'maxmind' &&
      (revHostnameSplit[0] === 'com' || revHostnameSplit[0] === 'dev') &&
      hostname !== 'www.maxmind.com'
    ) {
      targetHostname = hostname;
    }

    var that = this,
      param,
      request = new window.XMLHttpRequest(),
      uri =
        'https://' +
        (targetHostname || 'geoip-js.com') +
        '/geoip/v2.1/' +
        this.type +
        '/me?',
      httpParams = {
        referrer: location.protocol + '//' + location.hostname
      };

    if (this.alreadyRan) {
      return;
    }
    this.alreadyRan = 1;

    for (param in httpParams) {
      if (httpParams.hasOwnProperty(param) && httpParams[param]) {
        uri += param + '=' + encodeURIComponent(httpParams[param]) + '&';
      }
    }
    uri = uri.substring(0, uri.length - 1);

    request.open('GET', uri, true);
    request.onload = function () {
      if (typeof request.status === 'undefined' || request.status === 200) {
        that.returnSuccess(request.responseText);
      } else {
        var contentType = request.hasOwnProperty('contentType')
          ? request.contentType
          : request.getResponseHeader('Content-Type');

        var error;
        if (/json/.test(contentType) && request.responseText.length) {
          try {
            error = JSON.parse(request.responseText);
          } catch (e) {
            error = {
              code: 'HTTP_ERROR',
              error:
                'The server returned a ' +
                request.status +
                ' status with an invalid JSON body.'
            };
          }
        } else if (request.responseText.length) {
          error = {
            code: 'HTTP_ERROR',
            error:
              'The server returned a ' +
              request.status +
              ' status with the following body: ' +
              request.responseText
          };
        } else {
          error = {
            code: 'HTTP_ERROR',
            error:
              'The server returned a ' +
              request.status +
              ' status but either the server did not return a body' +
              ' or this browser is a version of Internet Explorer that hides error bodies.'
          };
        }

        that.returnError(error);
      }
    };
    request.ontimeout = function () {
      that.returnError({
        code: 'HTTP_TIMEOUT',
        error: 'The request to the GeoIP2 web service timed out.'
      });
    };
    request.onerror = function () {
      that.returnError({
        code: 'HTTP_ERROR',
        error:
          'There was a network error receiving the response from the GeoIP2 web service.'
      });
    };
    request.send(null);
  };

  exports.country = function (successCallback, errorCallback, options) {
    var l = new Lookup(successCallback, errorCallback, options, 'country');
    l.getGeoIPResult();
    return;
  };

  exports.city = function (successCallback, errorCallback, options) {
    var l = new Lookup(successCallback, errorCallback, options, 'city');
    l.getGeoIPResult();
    return;
  };

  exports.insights = function (successCallback, errorCallback, options) {
    var l = new Lookup(successCallback, errorCallback, options, 'insights');
    l.getGeoIPResult();
    return;
  };

  return exports;
})();
