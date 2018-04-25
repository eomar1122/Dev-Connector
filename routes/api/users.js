const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const keys = require('../../config/keys');
const passport = require('passport');

// Load Input Validation
const validateRegisterInput = require('../../validation/register');
const validateLoginInput = require('../../validation/login');


// Load User model
const User = require('../../models/User');


// @ route   Get api/users/test
// @desc     Tests user route
// @access   Public
router.get('/test', (req, res) => {
  res.json({msg: "Users Works"});
});

// @ route   Get api/users/register
// @desc     Register user
// @access   Public
router.post('/register', (req, res) => {

  // Validate inputs
  const { errors, isValid } = validateRegisterInput(req.body);

  // check if there is an input error
  if(!isValid) {
    return res.status(400).json(errors);
  }

  User.findOne({
    email: req.body.email
  })
  .then(user => {
    if(user) {
      errors.email = 'Email already exists';
      return res.status(400).json(errors);
    } else {
      const avatar = gravatar.url(req.body.email, {
        s: '200',   // Size
        r: 'pg',    // Rating
        d: 'mm'     // Default
      });

      const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        avatar,
        password: req.body.password
      });
      // Generate a salt and hash the password
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if(err) throw err;
          newUser.password = hash;
          // Save
          newUser.save()
            .then(user => {
              res.json(user);
            })
            .catch(err => console.log(err));
        })
      })
    }
  })
});

// @route    Get api/users/login
// @desc     Login user / Returning JWT Token
// @access   Public
router.post('/login', (req, res) => {

  // Validate inputs
  const { errors, isValid } = validateLoginInput(req.body);

  // check if there is an input error
  if(!isValid) {
    return res.status(400).json(errors);
  }

  const email = req.body.email;
  const password = req.body.password;

  // Find a user by email
  User.findOne({
    email
  })
  .then(user => {
    // Check for user
    if(!user) {
      errors.email = 'User not found';
      return res.status(404).json(errors);
    } 

    // Check password
    bcrypt.compare(password, user.password)
      .then(isMatch => {
        if(isMatch) {
          // User matched
          const payload = { id: user.id, name: user.name, avatar: user.avatar }; // Create JWT Payload

          // Sign Token  -- pass in payload with user information, key, and expiration time
          jwt.sign(payload, keys.secretOrKey, { expiresIn: 3600 }, (err, token) => {
            // Send a token as a response
            res.json({
              success: true,
              token: 'Bearer ' + token 
            });
          });
        } else {
          errors.password = 'Password incorrect';
          return res.status(400).json(errors);
        }
      });
  });
});

// @ route   Get api/users/current
// @desc     Return current user
// @access   Private
router.get('/current', passport.authenticate('jwt', { session: false }), (req, res) => {
  // res.json({ msg: 'Success' });
  res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email
  });
});




module.exports = router;