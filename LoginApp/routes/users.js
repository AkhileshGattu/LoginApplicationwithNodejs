const express = require('express');
var router = express.Router();

//Including passport and LocalStategy
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

//Getting the user Schema
var User = require('../models/user');
//get register page
router.get('/register', function(req, res){
  res.render('register');
});


//Login
router.get('/login', function(req, res){
  res.render('login');
});

//Resgestering User
router.post('/register', function(req, res){
  var name = req.body.name;
  var email = req.body.email;
  var username = req.body.username;
  var password = req.body.password;
  var password2 = req.body.password2;

  //Validating the registeration details
  req.checkBody('name', 'Name is required').notEmpty();
  req.checkBody('email', 'Email is required').notEmpty();
  req.checkBody('email', 'Email is not valid').isEmail();
  req.checkBody('username', 'Username is required').notEmpty();
  req.checkBody('password', 'Password is required').notEmpty();
  req.checkBody('password2', 'Passwords does not match').equals(req.body.password);

  //Calling errors function
  var errors = req.validationErrors();

  if (errors) {
    req.render('register', {
      errors:errors
    });
  }
  else {
      var newUser = new User({
        name: name,
        email: email,
        username: username,
        password: password
      });

      //Calling the cerateUser method in the model
      User.createUser(newUser, function(err, user){
        if (err) throw err;
        console.log(user);
      });

      //Setting message for the user to show user creation confirmation
      req.flash('success_msg', 'You are registered and can now login');

      //redirecting to login page after registeration
      res.redirect('/users/login');
  }
});

//passportjs Local Strategy
passport.use(new LocalStrategy(
  function(username, password, done) {
    User.getUserByUsername(username, function(err, user){
      if(err) throw err;
      if(!user){
        return done(null, false, {message: 'Unknown User'});
      }

      //If user exists then compare the Passwords
      User.comparePassword(password, user.password, function(err, isMatch){
        if(err) throw err;
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, {message: 'Invalid Password'});
        }
      });
    });
  }
));

//Serialize and deSerialize users
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

// Checking for Login
router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect: '/users/login', failureFlash: true}),
  function(req, res) {
    res.redirect('/');
  });
//For logout
router.get('/logout', function(req, res){
  req.logout();
  //req.flash('success_msg', 'You are logged out');
  res.redirect('/users/login');
})

module.exports =  router;
