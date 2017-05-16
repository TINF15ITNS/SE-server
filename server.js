var jwt = require('jsonwebtoken')
  , uuidv4 = require('node-uuid')
  , grpc = require('grpc')
  , MongoClient = require('mongodb').MongoClient
  , assert = require('assert')
  , crypto = require('crypto');

var apiProto = grpc.load('./protos/service.proto').friendscommAPI
var mongoUrl = 'mongodb://localhost:27017/friendscomm'
const SECRET = 'geheimnisDesGrauens'



var db = MongoClient.connect(mongoUrl, (err, db) => {
  if(err != null) {
    console.log("Error connecting to database")
    console.log(err)
    process.exit(1)
  }
  console.log('Successfully connected to database')
  return db
})

var server = new grpc.Server()
server.addService(apiProto.ServerService.service, {
  register: register,
  login: login,
  updateProfile: updateProfile,
  updatePassword: updatePassword,
  deleteProfile: deleteProfile,
  searchForProfile: searchForProfile,
  getProfileDetails: getProfileDetails
})
server.bind('0.0.0.0:50051', grpc.ServerCredentials.createInsecure())
server.start()




connectToDB = function() {
  
}

storeNewUserInDB = function() {

}

function searchForUserByName(nickname, callback) {
  db.collection('users').find({nickname: nickname}).count( res => {
    if(res == 0) {
      callback(true)
    } else {
      callback(false)
    }
  })
}

function getUserByName(nickname, callback) {
  storedUser = db.collection('users').findOne({nickname: nickname})
  callback(storedUser)
}

getUserByID = function() {

}

function generateToken(nickname) {
  return jwt.sign({nickname: nickname}, SECRET)
}

function verifyToken() {

}

// Password Hashing
// ================

function hashPassword(password) {
  var salt = crypto.randomBytes(128).toString('base64')
  var iterations = 10000
  var hash = crypto.pbkdf2(password, salt, iterations)
  return {
    salt: salt,
    hash: hash,
    iterations: iterations
  }
}
function isPasswordValid(savedHash, savedSalt, savedIterations, passwordAttempt) {
    return savedHash == crypto.pbkdf2(passwordAttempt, savedSalt, savedIterations)
}

// Implementations of gRPC functions
// =================================

function register(call,callback) {
  var metadata = call.metadata;
  var userdata = call.request;
  console.log('Registering new user:\n')
  console.log(userdata)
  searchForUserByName(userdata.nickname, (registrationPossible) => {
    if(registrationPossible) {
      newUser = new User(userdata.nickname, userdata.password)
      db.collection('users').insertOne(newUser, (err, r) => {
        if(err != null) {
          callback(err, {success: false})
        } else {
          callback(null, {success: true, token: generateToken(newUser.nickname)})
        }
      })
    }
  })
}

function login(call, callback) {
  var metadata = call.metadata
  var userdata = call.request
  console.log('Logging In:\n')
  console.log(userdata)
  getUserByName(userdata.nickname, storedUser => {
    if(storedUser != null && isPasswordValid(storedUser.hash, storedUser.salt, storedUser.iterations, userdata.password)) {
      callback(null, {success: true, token: generateToken(userdata.nickname)})
    } else {
      callback(null, {success: false})
    }
  })
  //if(call.request.user == 'daniel@laube.online' && call.request.password == '12345') {
    //var token = jwt.sign({ user: call.request.user }, 'geheimnisDesGrauens');
		//callback(null, {token: token, success: true}); 
  //} else {
		////callback(null, {message: 'Login failed'});
      //callback(null, {token: "Login failed", success: false});
  //}
}

function updateProfile(call, callback) {

}

function updateProfile(call, callback) {

}

function updatePassword(call, callback) {

}

function deleteProfile(call, callback) {

}

function searchForProfile(call, callback) {

}

function getProfileDetails(call, callback) {

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

function User(nickname, password) {
  this.nickname = nickname
  passwordData = hashPassword(password)
  this.hash = passwordData.hash
  this.salt = passwordData.salt
  this.iterations = passwordData.iterations
}
