//load bcrypt
var bCrypt = require('bcrypt-nodejs');
var db = require("../../models");
var LocalStrategy = require('passport-local').Strategy;

module.exports = function (passport) {
  passport.serializeUser(function (user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function (id, done) {
    db.User.findById(id).then(function(user){      
      return done(null, user);
    })    
  });

  //LOCAL SIGNUP
  passport.use('local-signup', new LocalStrategy({
      usernameField: "firstname",
      passwordField: 'email',
      passReqToCallback: true // allows us to pass back the entire request to the callback
    },

    function (req, firstname, email, done) {
      var generateHash = function (password) {
        return bCrypt.hashSync(password, bCrypt.genSaltSync(8), null);
      };

      db.User.findOne({
        where: {
          email: email
        }
      }).then(function (user) {        
        if (user) {
          return done(null, false, {
            message: 'That email is already taken'
          });
        } else {
          var userPassword = generateHash(req.body.password);
          var data = {
            email: email,
            password: userPassword,
            firstname: firstname,
            lastname: req.body.lastname,
            username: req.body.username,
          };

          db.User.create(data).then(function (newUser, created) {
            if (!newUser) {
              return done(null, false);
            }

            if (newUser) {              
              return done(null, newUser);
            }
          });
        }
      });
    }
  ));


  passport.use("local-signin", new LocalStrategy({
      usernameField: "email",
      passwordField: "password",
      passReqToCallback: true
    },

    function (req, email, password, done) {
      db.User.findOne({
        where: {
          email: email
        }
      }).then(function (user) {
        if (!user) {
          return done(null, false, {
            message: "Email not valid"
          });
        }       

        var isMatch = bCrypt.compareSync(password, user.password);

        if(!isMatch){
          return done(null, false, {message: "Password is not match"});
        }
        return done(null, user);
      }).catch(function(err){
        console.log(err);
        return done(null, false, {message: "Something went wrong witth the login"});
      })
    }))
}