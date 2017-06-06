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
  deleteUser: deleteUser,
  searchUser: searchUser,
  getUserDetails: getUserDetails
})
server.bind(config.grpc.uri, grpc.ServerCredentials.createInsecure())
server.start()
log.info({uri: config.grpc.uri}, 'Started gRPC server')

// Database operations
// ===================

function insertUser(user, callback) {
  log.info({user : user}, 'inserting user in db')
  if(user != null) {
    db.collection('users').insertOne(user, (err, r) => {
      return callback(err, r.insertedCount == 1 && r.result.ok == 1)
    })
  } else {
    return callback(new Error('EmptyArgument'), false)
  }
}

function searchForUser(nickname, callback) {
  log.info({nickname: nickname}, 'looking for user in db')
  db.collection('users').find({nickname: nickname}).count((err, count) => {
    if(err != null) {
    log.error({error: err}, 'Error Searching db')
    return callback(err, null)
    }
    else if(count == 0) {
      log.info({nickname: nickname}, 'no user found in db')
      return callback(null, false)
    } else {
      log.info({nickname: nickname}, 'found a user in db')
      return callback(null, true)
    }
  })
}

function getUser(nickname, callback) {
  log.info({nickname: nickname}, 'getting user from db')
  db.collection('users').find({nickname: nickname}).toArray((err, docs) => {
    if(err != null) {
      return callback(err, null)
    }
    if(docs.length != 1) {
      return callback(null, null)
    } else {
      return callback(null, docs[0])
    }
  })
}

// extracts the token from metadata, verifies the correct signature
// the callback takes a verified existing nickname as second argument,
// if none was found an error is returned as first argument
function loginWithToken(metadata, callback) {
  //return callback(null, 'fabi')
  jwt.verify(call.metadata.getKey('token'), SECRET, (err, decoded) => {
    if(err != null) {
      return callback(new Error('Authentication Error'), null)
    }
    nickname = decoded.nickname
    issued_at = decoded.iat
    if(!validNickname(nickname)) {
      return callback(new Error('Authentication Error'), null)
    } else {
      getUser(nickname, (err, user) => {
        if(err != null || user == null) {
          return callback(new Error('AuthenticationError'), null)
        }
        else if(user.token.issued_at != issued_at) {
          return callback(new Error('AuthenticationError'), null)
        } else {
          return callback(null, nickname)
        }
      }) 
    }
  })
    //var decoded = jwt.verify(metadata.get('token')[0], SECRET);
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
  var re = /^\w*$/; //any length is allowed but only letters and numbers
  return re.test(nickname);
}

function validPassword(password) {
  var re = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/; //length >= 6, one capital letter, one lowercase letter and one number
  return re.test(password);
}

function validName(name) {
  var re = /^[a-zA-Z'- ]+$/; //Letters, [-], ['] and [ ]
  return re.test(name);
}
function validSurname(surname) {
  var re = /^[a-zA-Z'- ]+$/; //Letters, [-], ['] and [ ]
  return re.test(surname);
}
function validBirthday(birthday) {
  return Date.parse(birthday) < Date.now(); //Born before this moment?
}
function validPhone(phone) {
  var re = /^[0-9]*$/; //only numbers
  return re.test(phone);
}
function validEmail(email) {
  //E-Mail validation according to the HTML5 spec: https://www.w3.org/TR/html5/forms.html#valid-e-mail-address
  var re = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return re.test(email);
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
        new_user = new User(req.nickname, req.password)
        new_issued_at = Date.now()
        new_token = jwt.sign({nickname: req.nickname, iat: new_issued_at}, SECRET)
        new_user.token = {}
        new_user.token.issued_at = new_issued_at
        console.log(new_user)
        insertUser(new_user, (err, success) => {
          if(err != null) {
            return callback(null, {success: false})
          } else {
            callback(null, {success: success, token: new_token})
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
    getUser(req.nickname, (err, stored_user) => {
      if(err != null) {
        log.info('Login not successfull')
        return callback(null, {success: false})
      }
      else if(stored_user != null && validatePassword(stored_user.password.hash, stored_user.password.salt, stored_user.password.iterations, req.password)) {
        new_issued_at = Date.now()
        new_token = jwt.sign({nickname: req.nickname, iat: new_issued_at}, SECRET)
        db.collection('users').updateOne({nickname: req.nickname}, {$set: {token: {issued_at: new_issued_at}}}, (err, r) => {
          if(err != null) {
            log.info('Login not successfull')
            return callback(null, {success : false})
          } else {
            log.info('Login successfull')
            return callback(null, {success: true, token: new_token})
          }
        })
      } else {
        log.info('Login not successfull')
        return callback(null, {success: false})
      }
    })
  } else {
    log.info('Login not successfull')
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
    else if(validPassword(req.old_password) && validPassword(req.new_password)) {
      getUser(nickname, (err, stored_user) => {
        if(err != null) {
          return callback(null, {success: false})
        }
        else if(stored_user != null && validatePassword(stored_user.password.hash, stored_user.password.salt, stored_user.password.iterations, req.old_password)) {
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

//TODO: Nach Todolisten, etc suchen die mit dem account verbunden sind und ebenfalls löschen!
function deleteUser(call, callback) {
  var metadata = call.metadata
  var req = call.request
  loginWithToken(metadata, (err, nickname) => {
    if(err != null) {
      log.info("call with insufficient credentials")
      return callback(null, {success: false})
    }
    if(validPassword(req.password)) {
      getUser(nickname, (err, stored_user) => {
        if(err != null) {
          return callback(null, {success: false})
        }
        else if(stored_user != null && validatePassword(stored_user.password.hash, stored_user.password.salt, stored_user.password.iterations, req.password)) {
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

function searchUser(call, callback) {
  var metadata = call.metadata
  var req = call.request
  loginWithToken(metadata, (err, nickname) => {
    if(err != null) {
      log.info("call with insufficient credentials")
      return callback(null, {success: false})
    } else {
      var data = call.request.get('query');
      var foundProfiles = db.collection('users').find({ $or: [ { nickname: data }, { name: data }, { surname: data }, { telNumber: data } ] }, {nickname: 1, _id:0}).toArray();
      
      if(foundProfiles.length == 0){
        return callback(null, {success: false, result: null});
      }
      else{
        return callback(null, {success: true, result: foundProfiles});
      }
    }
  })
}

function getUserDetails(call, callback) {

}

// Objects
// =======
function User(nickname, password) {
  this.nickname = nickname
  this.password = hashPassword(password)
}
