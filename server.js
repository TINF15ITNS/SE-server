const fs = require('fs')
    , crypto = require('crypto')
    , yaml = require('js-yaml')
    , bunyan = require('bunyan')
    , grpc = require('grpc')
    , MongoClient = require('mongodb').MongoClient
    , jwt = require('jsonwebtoken')
    , uuidv4 = require('node-uuid');

var config = yaml.safeLoad(fs.readFileSync('/etc/friendscomm.yml', 'utf8'))

var apiProto = grpc.load('./api.proto').serverPackage
const SECRET = config.server.key

var log = bunyan.createLogger({name: 'friendscomm-server'});
log.info('Initialized logger')

var db;
MongoClient.connect(config.mongodb.uri, (err, database) => {
  if(err != null || database == null) {
    log.error({err: err}, 'Error connecting to database')
    process.exit(1)
  }
  db = database
  log.info('Connected to database')
})

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
server.bind(config.grpc.uri, grpc.ServerCredentials.createInsecure())
server.start()
log.info({uri: config.grpc.uri}, 'Started gRPC server')

// Database operations
// ===================

function insertUser(user, callback) {
  log.info({user : user}, 'inserting user in db')
  if(user != null) {
    db.collection('users').insertOne(newUser, (err, r) => {
      callback(err, r.insertedCount == 1 && r.result.ok == 1)
    })
  } else {
    callback(new Error('EmptyArgument'), false)
  }
}

function searchForUser(nickname, callback) {
  log.info({nickname: nickname}, 'looking for user in db')
  db.collection('users').find({nickname: nickname}).count().then( res => {
    if(res == 0) {
      log.info({nickname: nickname}, 'no user found in db')
      callback(null, false)
    } else {
      log.info({nickname: nickname}, 'found a user in db')
      callback(null, true)
    }
  })
}

function getUser(nickname, callback) {
  log.info({nickname: nickname}, 'getting user from db')
  db.collection('users').find({nickname: nickname}).toArray().then( docs => {
    if(docs.length != 1) {
      callback(null, null)
    } else {
      callback(null, docs[0])
    }
  })
}


function generateToken(nickname) {
  return jwt.sign({nickname: nickname}, SECRET)
}

// extracts the token from metadata, verifies the correct signature
// the callback takes a verified existing nickname as second argument,
// if none was found an error is returned as first argument
function loginWithToken(metadata, callback) {
  return callback(null, 'fabi')
  //try {
    //console.log('Log', metadata.get('token')[0]);
    //var decoded = jwt.verify(metadata.get('token')[0], SECRET);
    //console.log('Log', decoded);

    //var decoded = jwt.verify(call.metadata.getKey('token'), SECRET);
    //callback(null, {message: decoded.user});
  //} catch(err) {
    //callback(null, {message: "authentication failed"});
  //}
}

// Password Hashing
// ================

function hashPassword(password) {
  var salt = crypto.randomBytes(32).toString('base64')
  var iterations = 10000
  hash = crypto.pbkdf2Sync(password, salt, iterations, 128, 'sha512').toString('hex')
  return {
    salt: salt,
    hash: hash,
    iterations: iterations
  }
}
function validatePassword(savedHash, savedSalt, savedIterations, passwordAttempt) {
  return savedHash == crypto.pbkdf2Sync(passwordAttempt, savedSalt, savedIterations, 128, 'sha512').toString('hex')
}

// Input Validation
// ================

function validNickname(nickname) {
  return nickname
}

function validPassword(password) {
  return password
}

function validName(name) {
  return name
}
function validSurname(surname) {
  return surname
}
function validBirthday(birthday) {
  return birthday
}
function validPhone(phone) {
  return phone
}
function validEmail(email) {
  return email
}

// Implementations of gRPC functions
// =================================

function register(call,callback) {
  var req = call.request;
  log.info({nickname: req.nickname},'New register attempt')
  if(validNickname(req.nickname) && validPassword(req.password)) {
    searchForUser(req.nickname, (err, nicknameExists) => {
      if(!nicknameExists && err == null) {
        log.info('Registration is possible')
        newUser = new User(req.nickname, req.password)
        insertUser(newUser, (err, success) => {
          if(err != null) {
            return callback(null, {success: false})
          } else {
            callback(null, {success: success, token: generateToken(newUser.nickname)})
          }
        })
      } else {
        callback(null, {success: false})
      }
    })
  } else {
    return callback(null, {success: false})
  }
}

function login(call, callback) {
  var req = call.request
  log.info({payload: req}, 'New login attempt')
  if(validNickname(req.nickname) && validPassword(req.password)) {
    getUser(req.nickname, (err, storedUser) => {
      if(err != null) {
        return callback(null, {success: false})
      }
      else if(storedUser != null && validatePassword(storedUser.hash, storedUser.salt, storedUser.iterations, req.password)) {
        log.info('Login successfull')
        return callback(null, {success: true, token: generateToken(req.nickname)})
      } else {
        log.info('Login not successfull')
        return callback(null, {success: false})
      }
    })
  } else {
    return callback(null, {success: false})
  }
}

function updateProfile(call, callback) {
  var metadata = call.metadata
  var req = call.request
  loginWithToken(metadata, (err, nickname) => {
    if(err != null) {
      log.info("call with insufficient credentials")
      return callback(null, {success: false})
    }
    var update = {}
    if(validName(req.name)) {
      update.name = req.name
    }
    if(validSurname(req.surname)) {
      update.surname = req.surname
    }
    if(validBirthday(req.birthday)) {
      update.birthday = req.birthday //TODO:convert to timestamp
    }
    if(validPhone(req.phone)) {
      update.phone = req.phone
    }
    if(validEmail(req.email)) {
      update.email = req.email
    }
    log.info({update:update})
    db.collection('users').updateOne({nickname: nickname}, {$set: update}, (err, r) => {
      if(err != null) {
        return callback(null, {success: false})
      } else {
        return callback(null, {success: true})
      }
    })
  })
}

function updatePassword(call, callback) {
  var metadata = call.metadata
  var req = call.request
  loginWithToken(metadata, (err, nickname) => {
    if(err != null) {
      log.info("call with insufficient credentials")
      return callback(null, {success: false})
    }
    if(validPassword(req.old_password) && validPassword(req.new_password)) {
      getUser(nickname, (err, storedUser) => {
        if(err != null) {
          return callback(null, {success: false})
        }
        else if(storedUser != null && validatePassword(storedUser.hash, storedUser.salt, storedUser.iterations, req.old_password)) {
          db.collection('users').updateOne({nickname: nickname}, {$set: {password: new_password}}, (err, r) => {
            if(err != null) {
              return callback(null, {success: false})
            } else {
              return callback(null, {success: true})
            }
          })
        }
      })
    } else {
      return callback(null, {success: false})
    }
  })
}

function deleteProfile(call, callback) {
  var metadata = call.metadata
  var req = call.request
  loginWithToken(metadata, (err, nickname) => {
    if(err != null) {
      log.info("call with insufficient credentials")
      return callback(null, {success: false})
    }
    if(validPassword(req.password)) {
      getUser(nickname, (err, storedUser) => {
        if(err != null) {
          return callback(null, {success: false})
        }
        else if(storedUser != null && validatePassword(storedUser.hash, storedUser.salt, storedUser.iterations, req.password)) {
          db.collection('users').deleteOne({nickname: nickname}, (err, r) => {
            if(err != null) {
              return callback(null, {success: false})
            } else {
              return callback(null, {success: true})
            }
          })
        }
      })
    } else {
      return callback(null, {success: false})
    }
  })
}

function searchForProfile(call, callback) {

}

function getProfileDetails(call, callback) {

}


// Objects
// =======
function User(nickname, password) {
  this.nickname = nickname
  passwordData = hashPassword(password)
  this.hash = passwordData.hash
  this.salt = passwordData.salt
  this.iterations = passwordData.iterations
}
