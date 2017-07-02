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
  getUserDetails: getUserDetails,
  getFriendList: getFriendList,
  addFriendToFriendlist: addFriendToFriendlist,
  removeFriendFromFriendlist: removeFriendFromFriendlist
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
    log.error({err: err}, 'Error Searching db')
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

//TODO allow filter of name
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

function removeFromFriendlistsOnDelete(nickname, friends, callback) {
  log.info({nickname: nickname, friends: friends}, 'removing deleted user from friendlists')
  db.collection('users').updateMany({ nickname: { $in: friends }}, { $pull: { listed_in_friendslist: nickname }}, (err, r) => {
    if(err != null) {
      return callback(null, false)
    } else {
      return callback(null, true)
    }
  })
}


// extracts the token from metadata, verifies the correct signature
// the callback takes a verified existing nickname as second argument,
// if none was found an error is returned as first argument
function loginWithToken(metadata, callback) {
  //var token = metadata.get('token').toString()
  var token = metadata.get('token')[0]
  log.info({token:token}, 'testing the token')
  jwt.verify(token, SECRET, (err, decoded) => {
    if(err != null) {
      log.error({err:err}, 'An error ocurred while verifying')
      return callback(new Error('Authentication Error'), null)
    }
    nickname = decoded.nickname
    issued_at = decoded.iat
    if(!validNickname(nickname)) {
      log.info({nickname:nickname},'no valid nickname')
      return callback(new Error('Authentication Error'), null)
    } else {
      getUser(nickname, (err, user) => {
        if(err != null || user == null) {
          log.error({err:err}, 'user not found in database')
          return callback(new Error('AuthenticationError'), null)
        }
        else if(user.token.issued_at != issued_at) {
          log.info('issued_at mismatch, not the most recent token')
          return callback(new Error('AuthenticationError'), null)
        } else {
          log.info({nickname: nickname}, 'call authentication successfull')
          return callback(null, nickname)
        }
      }) 
    }
  })
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
  var re = /^\w{1,}$/; //any length is allowed but only letters and numbers
  return re.test(nickname);
}

function validPassword(password) {
  var re = /.{6,}/; //length >= 6
  return re.test(password);
}

function validName(name) {
  var re = /^[a-zA-Z\u00C0-\u017F'\- ]+$/; //Letters, [-], ['], [ ] and accented characters
  return re.test(name);
}
function validSurname(surname) {
  var re = /^[a-zA-Z\u00C0-\u017F'\- ]+$/; //Letters, [-], ['], [ ] and accented characters
  return re.test(surname);
}
function validBirthday(birthday) {
  return birthday < Date.now(); //Born before this moment?
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
        log.info({token:new_token, secret:SECRET}, 'token issued')
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
  var res = { success: false }
  loginWithToken(metadata, (err, nickname) => {
    if(err != null) {
      log.info("call with insufficient credentials")
      return callback(null, res)
    } else if(validPassword(req.password)) {
      getUser(nickname, (err, stored_user) => {
        if(err != null) {
          log.error({err:err}, 'Error while getting User')
          return callback(null, res)
        } else if(stored_user != null && validatePassword(stored_user.password.hash, stored_user.password.salt, stored_user.password.iterations, req.password)) {
          removeFromFriendlistsOnDelete(nickname, stored_user.listed_in_friendslist, (err, r) => {
            if(!r) {
              log.warn({nickname:nickname, friends: stored_user.listed_in_friendslist}, 'error deleting deleted user from friendslist')
            } else {
              log.info({nickname:nickname, friends: store_user.friends_in_friendslist}, 'deleted deleted user from friendslist')
            }
          })
          db.collection('users').deleteOne({nickname: nickname}, (err, r) => {
            if(err != null) {
              log.error({err:err}, 'Error while deleting User from DB')
            } else {
              res.success = true
            }
            log.info({response:res}, 'callback')
            return callback(null, res)
          })
        } else {
          return callback(null, res)
        }
      })
    } else {
      return callback(null, res)
    }
  })
}

function searchUser(call, callback) {
  var metadata = call.metadata
  var req = call.request
  var res = { success: false }
  loginWithToken(metadata, (err, nickname) => {
    if(err != null) {
      log.info("call with insufficient credentials")
      return callback(null, res)
    } else {
      log.info("Search User")
      var query = req.query
      db.collection('users').find({ $or: [ { nickname: query }, { name: query }, { surname: query }, { telNumber: query } ] }, {nickname: 1, _id:0}, (err, data) => {
        if(err != null) {
          log.error({err:err}, 'Error while querying DB')
          return callback(null, res)
        } else {
          data.toArray((err, profiles) => {
            if(err != null) {
              log.error({err:err}, 'Error while converting data.toArray')
            } else if(profiles.length == 0) {
              log.info('no profiles found')
            } else {
              profiles = profiles.map(elem => elem.nickname)
              log.info({profiles: profiles}, 'converted to right array')
              res.nickname_result = profiles
              res.success = true
            }
            log.info({response:res}, 'callback')
            return callback(null, res)
          })
        }
      })
    }
  })
}


function getUserDetails(call, callback) {
  var metadata = call.metadata;
  var req = call.request;
  var res = { success: false }
  loginWithToken(metadata, (err, nickname) => {
    if (err != null) {
      log.info("call with insufficient credentials")
      return callback(null, res)
    } else if(!validNickname(req.nickname)) {
      log.info({nickname: req.nickname}, "Invalid nickname was sent")
      return callback(null, res)
    } else{
      getUser(req.nickname, (err, stored_user) => {
        if(err != null) {
          log.error({err: err},"Lookup of user unsuccessfull")
        } else if(stored_user == null) {
          log.info({nickname: req.nickname}, "no user found")
        } else {
          log.info({user: stored_user}, "found user, sending details")
          if('name' in stored_user) {res.name = stored_user.name}
          if('surname' in stored_user) {res.surname = stored_user.surname}
          if('birthday' in stored_user) {res.birthday = stored_user.birthday}
          if('phone' in stored_user) {res.phone = stored_user.phone}
          if('email' in stored_user) {res.email = stored_user.email}
          res.success = true
        }
        log.info({response:res}, 'callback')
        return callback(null, res)
      })
    }
  })
}


function getFriendList(call, callback) {
  var metadata = call.metadata;
  var req = call.request;
  var res = { success: false }
  loginWithToken(metadata, (err, nickname) => {
    if (err != null) {
      log.info("call with insufficient credentials")
      return callback(null, res)
    } else{
      db.collection('users').find({nickname: nickname}, {}).toArray((err, users) => {
        if(err != null) {
          log.error({err: err},"Lookup of user unsuccessfull")
        } else if(users.length != 1) {
          log.info("not 1 user found")
        } else {
          log.info({user: stored_user}, "found user, sending friendlist")
          if('friendlist' in users[0]) {res.friendlist = users[0].friendlist}
          res.success = true
        }
        log.info({response:res}, 'callback')
        return callback(null, res)
      })
    }
  })
}


function addFriendToFriendlist(call, callback) {
  var metadata = call.metadata;
  var req = call.request;
  var res = { success: false }
  loginWithToken(metadata, (err, nickname) => {
    if (err != null) {
      log.info("call with insufficient credentials")
      return callback(null, res)
    } else{
      if(!validNickname(req.nickname)) {
      log.info({nickname: req.nickname}, 'no valid friend nickname was given')
      return callback(null, res)
      } else{
        getUser(req.nickname, (err, friend) => {
          if(err != null) {
            log.error({err: err},"Error looking up friend")
            return callback(null, res)
          } else if(friend == null) {
            log.info("friend not found in db")
            return callback(null, res)
          } else {
            log.info({nickname: req.nickname}, "found friend, adding to friendlist")
            db.collection('users').updateOne({ nickname: nickname },{ $addToSet: { friendlist: req.nickname }}, (err, r) => {
              if(err != null) {
              log.error({err: err},"Error adding to database array")
              } else{
                db.collection('users').updateOne({ nickname: friend.nickname}, {$addToSet: { listed_in_friendslist: nickname }}).then( (err, r) => {
                  if(err != null) {
                    log.warn({err:err}, 'Error updating listed_in_friendslist')
                  }
                })
                res.success = true
              }
              log.info({response:res}, 'callback')
              return callback(null, res)
            })
          }
        })
      }
    }
  })
}


function removeFriendFromFriendlist(call, callback) {
  var metadata = call.metadata;
  var req = call.request;
  var res = { success: false }
  loginWithToken(metadata, (err, nickname) => {
    if (err != null) {
      log.info("call with insufficient credentials")
      return callback(null, res)
    } else{
      if(!validNickname(req.nickname)) {
      log.info({nickname: req.nickname}, 'no valid friend nickname was given')
      return callback(null, res)
      } else{
        searchForUser(req.nickname, (err, found) => {
          if(err != null) {
            log.error({err: err},"Error looking up friend")
            return callback(null, res)
          } else if(!found) {
            log.warn("friend not found in db")
            db.collection('users').updateOne({ nickname: nickname },{ $pull: { friendlist: req.nickname }}, (err, r) => {
              if(err != null) {
              log.error({err: err},"Error removing from database array")
              } else{
                res.success = true
              }
              log.info({response:res}, 'callback')
              return callback(null, res)
            })
          } else {
            db.collection('users').updateOne({ nickname: nickname },{ $pull: { friendlist: req.nickname }}, (err, r) => {
              if(err != null) {
              log.error({err: err},"Error removing from database array")
              } else{
                db.collection('users').updateOne({ nickname: friend.nickname}, {$pull: { listed_in_friendslist: nickname }}).then( (err, r) => {
                  if(err != null) {
                    log.warn({err:err}, 'Error updating listed_in_friendslist')
                  }
                })
                res.success = true
              }
              log.info({response:res}, 'callback')
              return callback(null, res)
            })
          }
        })
      }
    }
  })
}


// Objects
// =======
function User(nickname, password) {
  this.nickname = nickname
  this.password = hashPassword(password)
}
