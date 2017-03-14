const express = require('express');
var router = express.Router();

//get home page
router.get('/', function(req, res){
  res.render('index');
});

// Funcation to authenticate whether the user is logged in or not
function ensureAuthenticated(req, res, next){
  if (req.isAuthenticated()) {
    return next();
  } else {
    req.flash('error_msg', 'You are not logged in');
    res.redirect('/users/login');
  }
}

module.exports =  router;
