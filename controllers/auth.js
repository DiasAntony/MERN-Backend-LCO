const User = require("../models/user");
const { check, validationResult } = require("express-validator");
var jwt = require("jsonwebtoken");
var expressJwt = require("express-jwt");


exports.signup = (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: errors.array()[0].msg
    });
  }
  // all data from req.body not specific one like (req.body.email) becouse signIN up we need all information about user like{name,lastname,email,password,ect,.} from that route page body
// data all about frontend body or custom postman request
  const user = new User(req.body);
  user.save((err, user) => {
    if (err) {
      return res.status(400).json({
        err: "NOT able to save user in DB"
      });
    }
    // reponse for checking purpose so we only take these 3 fields
    res.json({
      name: user.name,
      email: user.email,
      id: user._id
    });
  });
};

exports.signin = (req, res) => {
  const errors = validationResult(req);
  const { email, password } = req.body;

  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: errors.array()[0].msg
    });
  }
// {email} fom above email:req.body.email so why we used in above this is confusing you!!! {} curly braces from db meathod like action
  User.findOne({ email }, (err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: "USER email does not exists"
      });
    }
// from checking password match from securepassword!!!! ==> userSchema
    if (!user.autheticate(password)) {
      return res.status(401).json({
        error: "Email and password do not match"
      });
    }

    //create token
    const token = jwt.sign({ _id: user._id }, process.env.SECRET);
    //put token in cookie
    res.cookie("token", token, { expire: new Date() + 9999 });
// not neccesary for send to frontend but its toutorial so on!!!
    //send response to postman or front end(without password!!!)
    const { _id, name, email, role } = user;
    // user._id , user.name ^^^👇👇👇
    // below response for f.e already we saw
    // we saw too localstorage to F.E
    return res.json({ token, user: { _id, name, email, role } });
  });
};

exports.signout = (req, res) => {
  // clearthe cookie for unauthorize the user
  res.clearCookie("token");
  res.json({
    message: "User signout successfully"
  });
};


// if you get token then only your'e a authendicated or signin persion in in this application
// only signin or authendication user only go to specific route
//protected routes
exports.isSignedIn = expressJwt({
  secret: process.env.SECRET,
  userProperty: "auth"
});

// req.profile & req.profile._id setup from F.E req.auth & req.auth._id setup from above middleware(isSignedIn)
// video 07 section 07
//custom middlewares
exports.isAuthenticated = (req, res, next) => {
  let checker = req.profile && req.auth && req.profile._id == req.auth._id;
  if (!checker) {
    return res.status(403).json({
      error: "ACCESS DENIED"
    });
  }
  next();
};
// admin only update the products
exports.isAdmin = (req, res, next) => {
  if (req.profile.role === 0) {
    return res.status(403).json({
      error: "You are not ADMIN, Access denied"
    });
  }
  next();
};


