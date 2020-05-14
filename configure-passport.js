'use strict';

// Passport Strategy configuration

const passport = require('passport');
const passportLocal = require('passport-local');

const PassportLocalStrategy = passportLocal.Strategy;

const bcrypt = require('bcrypt');
const User = require('./models/user');


passport.serializeUser((user, callback) => {
  callback(null, user._id);
});

passport.deserializeUser((id, callback) => {
  User.findById(id)
    .then(user => {
      callback(null, user);
    })
    .catch(error => {
      callback(error);
    });
});

passport.use(
  'sign-up',
  new PassportLocalStrategy({}, (username, password, callback) => {
    // Perform your authentication logic and call the callback function,
    // passing it null in the first parameter and the user document in the second
    let user;
    User.findOne({
      username
    })
    .then(document => {
      user = document;
      if (document) {
        return bcrypt.compare(password, user.passwordHash)
      } else {
        return Promise.reject(new Error('User not valid'));
      }
    })
    .then(pw => {
      if (pw) {
        callback(null, user);
      } else {
        return Promise.reject(new Error('Wrong Password'));
      }
    })
    .catch(error => {
      callback(error)
    })
  })
);

