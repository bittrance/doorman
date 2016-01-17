var expect = require('chai').expect;
var everyauth = require('everyauth');
var httpMocks = require('node-mocks-http');

var auth = require('../lib/auth');

function makeMockModule(success) {
  return {
    title: 'mockModule',
    authorize: function(auth) {
      return success;
    },
    decorate: function(req, auth) {
      req.username = 'mockWasHere';
    }
  };
};

function makeMockConfig(mockModule) {
  var conf = {
    modules: { test: mockModule }
  };
  everyauth.test = mockModule;

  return conf;
};

describe('checkUser', function() {
  it('successful auth decorates request and calls supplied proxy', function(done) {
    var mockModule = makeMockModule(true);
    var conf = makeMockConfig(mockModule);

    function proxyMock(req, res, next) {
      expect(req.username).to.equal('mockWasHere');
      done();
    };

    var checkUser = auth.makeUserChecker(proxyMock, conf);

    var req = httpMocks.createRequest({
      method: 'GET',
      url: '/foo/bar',
      session: { auth: { test: {} } }
    });
    req.flash = function() {};

    var res = httpMocks.createResponse();

    checkUser(req, res, undefined);
  });


  it('failed auth flashes user and calls next middleware', function(done) {
    var mockModule = makeMockModule(false);
    var conf = makeMockConfig(mockModule);

    function proxyMock(req, res, next) {
      throw new Error();
    };

    var checkUser = auth.makeUserChecker(proxyMock, conf);

    var req = httpMocks.createRequest({
      method: 'GET',
      url: '/foo/bar'
    });

    var flashed;
    req.flash = function(msg) {
      flashed = msg;
    };

    var res = httpMocks.createResponse();

    checkUser(req, res, done);
    expect(flashed).to.be.empty;
  });
});
