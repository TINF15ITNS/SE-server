var PROTO_PATH = __dirname + '/protos/server.proto';

var jwt = require('jsonwebtoken');

var grpc = require('grpc');
var hello_proto = grpc.load(PROTO_PATH).serverPackage;



function sayHello(call, callback) {
  callback(null, {message: 'Hallo ' + call.request.name});
}

function login(call, callback) {
  var metadata = call.metadata;
  console.log('neuer login');
  if(call.request.user == 'daniel@laube.online' && call.request.password == '12345') {
    var token = jwt.sign({ user: call.request.user }, 'geheimnisDesGrauens');
	  callback(null, {token: token, success: true}); 
  } else {
	  //callback(null, {message: 'Login failed'});
      callback(null, {token: "Login failed", success: false});
  }
}



function getUserName(call, callback) {
  try {
    console.log('Log', metadata.get('token')[0]);
    var decoded = jwt.verify(metadata.get('token')[0], 'geheimnisDesGrauens');
    console.log('Log', decoded);

    var decoded = jwt.verify(call.metadata.getKey('token'), 'geheimnisDesGrauens');
    callback(null, {message: decoded.user});
  } catch(err) {
    callback(null, {message: "authentication failed"});
  }
}

function main() {
  var server = new grpc.Server();
  server.addProtoService(hello_proto.ServerService.service, {sayHello: sayHello, login:login});
  server.bind('0.0.0.0:50051', grpc.ServerCredentials.createInsecure());
  server.start();
}

main();