'use strict';

// Passport Strategy configuration

const passport = require('passport');
const passportLocal = require('passport-local');
const passportGithub = require('passport-github');
const bcrypt = require('bcrypt');

const LocalStrategy = passportLocal.Strategy;
const GithubStrategy = passportGithub.Strategy;

const PassportLocalStrategy = passportLocal.Strategy;

const User = require('./models/user');

passport.serializeUser((user, callback) => {
  callback(null, user._id);
});

passport.deserializeUser((id, callback) => {
  User.findById(id)
    .then((user) => {
      callback(null, user);
    })
    .catch((error) => {
      callback(error);
    });
});

passport.use(
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_API_CLIENT_ID,
      clientSecret: process.env.GITHUB_API_CLIENT_SECRET,
      callbackURL: 'http://localhost:3000/authentication/github-callback',
      scope: 'user:email'
    },
    (accessToken, refreshToken, profile, callback) => {
      const name = profile.displayName;
      const email = profile.emails.length ? profile.emails[0].value : null;
      const photo = profile._json.avatar_url;
      const githubId = profile.id;

      User.findOne({
        
        githubId
      })
      
        .then((user) => {
          //console.log(user)
          if (user) {
            return Promise.resolve(user);
          } else {
            return User.create({
              email,
              name,
              photo,
              githubId
            });
          }
        })
        .then((user) => {
          callback(null, user);
        })
        .catch((error) => {
          callback(error);
        });
    }
  )
);

passport.use(
  'sign-up',
  new LocalStrategy({}, (username, password, callback) => {
    // Perform your authentication logic and call the callback function,
    // passing it null in the first parameter and the user document in the second
    bcrypt
      .hash(password, 15)
      .then((hashandsalt) => {
        return User.create({
          username,
          passwordHash: hashandsalt
        });
      })
      .then((user) => {
        callback(null, user);
      })
      .catch((error) => {
        callback(error);
      });
  })
);

passport.use(
  'sign-in',
  new LocalStrategy({}, (username, password, callback) => {
    let user;
    User.findOne({
      username
    })
      .then((document) => {
        user = document;
        return bcrypt.compare(password, user.passwordHash);
      })
      .then((result) => {
        if (result) {
          callback(null, user);
        } else {
          return Promise.reject(new Error('Passwords do not match.'));
        }
      })
      .catch((error) => {
        callback(error);
      });
  })
);



passport.use(
  'sign-up',
  new PassportLocalStrategy({}, (username, password, callback) => {
    // Perform your authentication logic and call the callback function,
    // passing it null in the first parameter and the user document in the second
    bcrypt
      .hash(password, 15)
      .then((hashandsalt) => {
        return User.create({
          username,
          passwordHash: hashandsalt
        });
      })
      .then((user) => {
        callback(null, user);
      })
      .catch((error) => {
        callback(error);
      });
  })
);

passport.use(
  'sign-in',
  new PassportLocalStrategy({}, (username, password, callback) => {
    User.findOne({
      username
    })
      .then((user) => {
        callback(null, user);
      })
      .catch((error) => {
        callback(error);
      });
  })
);


