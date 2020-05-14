'use strict';

const { Router } = require('express');
const authenticationRouter = Router();

const passport = require('passport');

const ensureLogin = require('connect-ensure-login');

authenticationRouter.get('/private-page', ensureLogin.ensureLoggedIn(), (req, res, next) => {
  res.render(
    'passport/private'
  );
});

authenticationRouter.get('/sign-up', (req, res, next) => {
  //console.log(req.user);
  res.render('authentication/sign-up');
});

authenticationRouter.post(
  '/sign-up',
  passport.authenticate('sign-up', {
    successRedirect: '/',
    failureRedirect: '/authentication/sign-up'
  })
);

authenticationRouter.get('/sign-in', (req, res, next) => {
  res.render('authentication/sign-in');
});

authenticationRouter.post(
  '/sign-in',
  passport.authenticate('sign-in', {
    successRedirect: '/',
    failureRedirect: '/authentication/sign-in'
  })
);

authenticationRouter.post('/sign-out', (req, res, next) => {
  req.logout();
  res.redirect('/');
});

module.exports = authenticationRouter;
