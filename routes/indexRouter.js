const express = require("express");
const app = require("../app");
const indexRouter = express.Router();
const User = require("./../models//User.model");

const isLoggedIn = require("./../utils/isLoggedIn");

// GET   /secret
indexRouter.get("/secret", isLoggedIn, (req, res, next) => {
  const { _id } = req.session.currentUser;
  User.findById(_id)
    .then((user) => {
      const props = { user: user };
      res.render("Secret", props);
    })
    .catch((err) => console.log(err));
});

// Example: displaying content depending on if user is logged in or not
indexRouter.get("/example", (req, res, next) => {
  const userIsLoggedIn = Boolean(req.session.currentUser);

  const props = { userIsLoggedIn };

  res.render("Example", props);
});

module.exports = indexRouter;
