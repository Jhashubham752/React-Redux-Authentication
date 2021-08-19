var express = require("express");
const bcrypt = require("bcrypt");
var router = express.Router();
const jwt = require("jsonwebtoken");
const auth = require("../Middleware/auth");
const User = require("../Model/auth");
const Joi = require("joi");

router.post("/register",async (req, res) => {
  const schema = Joi.object({
  name: Joi.string().min(3).max(30).required(),
  email: Joi.string().min(3).max(200).required().email(),
  password: Joi.string().min(6).max(200).required(),
  });

  const { error } = schema.validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  // let user = await User.findOne({ email: req.email.body });
  // if (user) return res.status(400).send("User already exists...");

  const { name, email, password, } = req.body;
  user = new User({ name, email, password });

  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(user.password, salt);
  await user.save();

  const jwtSecretKey = process.env.SECRET_KEY;
  const token = jwt.sign(
  {_id: user._id, name: user.name, email: user.email },
    jwtSecretKey
  );
    res.send(token);

  // try {
  //   let { name, email, password , passwordCheck  } = req.body;

  //   const newUser = new User({
  //     name,
  //     email,
  //     password,
  //     passwordCheck,
  //   });
  //   const savedUser = await newUser.save();
  //   res.json(savedUser);
  // } catch (err) {
  //   console.log(err);

  // }
});

router.post("/login", async (req, res) => {

  const schema = Joi.object({
    email: Joi.string().min(3).max(200).required().email(),
    password: Joi.string().min(6).max(200).required(),
  });

  const { error } = schema.validate(req.body);

  if (error) return res.status(400).send(error.details[0].message);

  let user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).send("Invalid email or password...");

  const validPassword = await bcrypt.compare(req.body.password, user.password);
  if (!validPassword)
    return res.status(400).send("Invalid email or password...");

  const jwtSecretKey = process.env.SECRET_KEY;
  const token = jwt.sign({ _id: user._id, name: user.name, email: user.email }, jwtSecretKey)

  res.send(token);
  // try {
  //   const { email, password } = req.body;

  //   const user = await User.findOne({ email: email });
  //   if (!user)
  //     return res
  //       .status(400)
  //       .json({ msg: "No account with this email has been registered." });

  //   const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY);
  //   console.log("token", token);
  //   res.json({
  //     token,
  //     user: {
  //     id: user._id,
  //     name: user.name,
  //     },
  //   });
  // } catch (err) {
  //   res.status(500).json({ error: err.message });
  // }
});

router.post("/tokenIsValid", async (req, res) => {
  try {
    const token = req.header("x-auth-token");
    if (!token) return res.json(false);

    const verified = jwt.verify(token, process.env.SECRET_KEY);
    if (!verified) return res.json(false);

    const user = await User.findById(verified.id);
    if (!user) return res.json(false);

    return res.json(true);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/", auth, async (req, res) => {
  const user = await User.findById(req.user);
  res.json({
    displayName: user.name,
    id: user._id,
  });
});

module.exports = router;
