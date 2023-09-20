// import modules
import 'dotenv/config';
import express from "express";
import bodyParser from "body-parser";
import ejs from "ejs";
import mongoose from "mongoose";
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from "passport-local-mongoose";
import Google from "passport-google-oauth20";
const GoogleStrategy = Google.Strategy;
import Facebook from "passport-facebook";
const FacebookStrategy = Facebook.Strategy;
import findOrCreate from "mongoose-findorcreate";



const app = express();
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.use(session({
    secret: 'this is my secret and i am not gonna show',
    resave: false,
    saveUninitialized: false

}));


app.use(passport.initialize());
app.use(passport.session());



mongoose.connect("mongodb://127.0.0.1:27017/UserDB");
// mongoose.set("useCreateIndex",true)        //deprication warning

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);




const User = mongoose.model("user", userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser((user, done) => {
    done(null, user.id);
});


passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id).exec(); // Execute the query and await the result
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});




//google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile)
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));



app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google", passport.authenticate('google', { scope: ["profile"] })

);


app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    });


app.get("/login", (req, res) => {
    res.render("login");
});
app.get("/register", (req, res) => {
    res.render("register");

});
app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err)
        } else {
            res.redirect("/")
        }
    });

})

app.get("/secrets",async (req, res) => {

    if (req.isAuthenticated()) {
        try{
         const foundUser = await User.find({"secret": {$ne:null}}).exec();
         if(foundUser){
            res.render("secrets",{userWithSecrets:foundUser});
         }
        }catch(err){
          console.log(err);
        };
    } else {
        res.redirect("/login");
    };


});

app.get("/submit", (req, res) => {

    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }

});

app.post("/submit", async (req, res) => {
    try {
        if (req.isAuthenticated()) {
            // User is authenticated, proceed with handling the request
            const submittedSecret = req.body.secret;
            const findUser = await User.findById(req.user._id).exec();
            if (findUser) {
                findUser.secret = submittedSecret;
                await findUser.save();
                res.redirect("/secrets");
            }
        } else {
            // User is not authenticated, redirect to login
            res.redirect("/login");
        }
    } catch (err) {
        console.log(err);
    }
});

app.post("/register", (req, res) => {

    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });

        };
    });



});

app.post("/login", (req, res) => {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    passport.authenticate("local")(req, res, () => {
        // This callback will be called after authentication succeeds or fails
        if (req.isAuthenticated()) {
            // User is authenticated, redirect to the secrets page
            res.redirect("/secrets");
        } else {
            // Authentication failed, redirect to the login page
            res.redirect("/login");
        }
    });

});








app.listen(3000, () => {
    console.log("server started at port 3000");
});