var express = require('express')
var app = express()
var passport = require('passport')
var session = require('express-session')
var bodyParser = require('body-parser')
var env = require('dotenv').load()
var exphbs = require('express-handlebars')
var PORT = process.env.PORT || 8080;
var path = require("path");



//For BodyParser
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());


// For Passport
app.use(session({
    secret: 'keyboard cat',
    resave: true,
    saveUninitialized: true
})); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions


//For Handlebars
app.set('views', './app/views')
app.engine('hbs', exphbs({
    extname: '.hbs'
}));
app.set('view engine', '.hbs');


app.get('/', function (req, res) {
    res.send('Welcome to Passport with Sequelize');
});


//Models
var models = require("./app/models");


//Routes
var authRoute = require('./app/routes/auth.js')(app, passport);


//load passport strategies
require('./app/config/passport/passport.js')(passport);

console.log("dir name: " + path.join(__dirname));
//Sync Database
models.sequelize.sync().then(function () {
    console.log('Nice! Database looks fine')
    app.listen(PORT, function (err) {
        if (!err)
            console.log("Site is live at " + PORT);
        else console.log(err)

    });

}).catch(function (err) {
    console.log(err, "Something went wrong with the Database Update!")
});