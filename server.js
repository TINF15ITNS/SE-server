var jwt = require('jsonwebtoken')
  , uuidv4 = require('node-uuid')
  , grpc = require('grpc')
  , MongoClient = require('mongodb').MongoClient
  , bunyan = require('bunyan')
  , assert = require('assert')
  , crypto = require('crypto');

var apiProto = grpc.load('./protos/service.proto').serverPackage
var mongoUrl = 'mongodb://localhost:27017/friendscomm'
const SECRET = 'geheimnisDesGrauens'

var log = bunyan.createLogger({name: 'friendscomm-server'});
log.info('Initialized logger')


MongoClient.connect(mongoUrl, (err, database) => {
  if(err != null) {
    log.error({err: err}, 'Error connecting to database')
    process.exit(1)
  }
  
  if(database == null) {
    log.error({err: err}, 'Error connecting to database')
    process.exit(1)
  }
  
  log.info('Successfully connected to database')
})

var db = MongoClient.db

var server = new grpc.Server()
server.addProtoService(apiProto.ServerService.service, {
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
log.info({port: 50051}, 'Successfully started gRPC server')


connectToDB = function() {
  
}

storeNewUserInDB = function() {

}

function searchForUserByName(nickname, callback) {
  MongoClient.connect(mongoUrl, (err, database) => {
  if(err != null) {
    log.error({err: err}, 'Error connecting to database')
    process.exit(1)
  }
  
  if(database == null) {
    log.error({err: err}, 'Error connecting to database')
    process.exit(1)
  }
  
  database.collection('users').find({nickname: nickname}).count().then(function(res) {
    if(res == 0) {
      callback(true)
    } else {
      callback(false)
    }
  })
  })
  
}

function getUserByName(nickname, callback) { 
  MongoClient.connect(mongoUrl, (err, database) => {
  if(err != null) {
    log.error({err: err}, 'Error connecting to database')
    process.exit(1)
  }
  
  if(database == null) {
    log.error({err: err}, 'Error connecting to database')
    process.exit(1)
  }
  
    database.collection('users').findOne({nickname: nickname}).then(function(storedUser) {
		callback(storedUser)  
    })
  })
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
  var hash = crypto.pbkdf2Sync(password, salt, iterations, 512, 'sha512').toString('hex');
  
  return {
    salt: salt,
    hash: hash,
    iterations: iterations
  }
}

function isPasswordValid(savedHash, savedSalt, savedIterations, passwordAttempt) {
    return savedHash == crypto.pbkdf2Sync(passwordAttempt, savedSalt, savedIterations, 512, 'sha512').toString('hex');
}

// Implementations of gRPC functions
// =================================

function register(call,callback) {
  var metadata = call.metadata;
  var userdata = call.request;
  
  log.info({payload: userdata},'New register attempt')
  searchForUserByName(userdata.nickname, (registrationPossible) => {
    if(registrationPossible) {
      log.info('Registration is possible')
      newUser = new User(userdata.nickname, userdata.password)

	MongoClient.connect(mongoUrl, (err, database) => {
        if(err != null) {
          log.error({err: err}, 'Error connecting to database')
          process.exit(1)
        }
        
        if(database == null) {
          log.error({err: err}, 'Error connecting to database')
          process.exit(1)
        }
        
        database.collection('users').insertOne(newUser, (err, r) => {
              if(err != null) {
                callback(null, {success: false})
              } else {
                callback(null, {success: true, token: generateToken(newUser.nickname)})
              }
        })
    })
	  
	  
    } else {
      callback(null, {success: false})
    }
  })
}

function login(call, callback) {
  var metadata = call.metadata
  var userdata = call.request
  log.info({payload: userdata}, 'New login attempt')
  getUserByName(userdata.nickname, storedUser => {
	
	console.log(storedUser)
	
    if(storedUser != null && storedUser != "" && isPasswordValid(storedUser.hash, storedUser.salt, storedUser.iterations, userdata.password)) {
      log.info('Login successfull')
      callback(null, {success: true, token: generateToken(userdata.nickname)})
    } else {
      log.info('Login not successfull')
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
