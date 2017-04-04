var PROTO_PATH = __dirname + '/protos/server.proto';

var grpc = require('grpc');
var hello_proto = grpc.load(PROTO_PATH).serverPackage;

function sayHello(call, callback) {
  callback(null, {message: 'Hallo ' + call.request.name});
}

function login(call, callback) {
  if(call.request.user == 'daniel@laube.online' && call.request.password == '12345') {
	  callback(null, {message: 'Login successfull'}); 
  } else {
	  callback(null, {message: 'Login failed'});
  }
}

function main() {
  var server = new grpc.Server();
  server.addProtoService(hello_proto.ServerService.service, {sayHello: sayHello, login:login});
  server.bind('0.0.0.0:50051', grpc.ServerCredentials.createInsecure());
  server.start();
}

main();