var createError = require("http-errors");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
var dotenv = require("dotenv");
dotenv.config();

var jwt = require("jsonwebtoken");
var cookieParser = require("cookie-parser");
var logger = require("morgan");
const bcrypt = require('bcrypt');

var userRouter = require("./routes/user");

var app = express();
app.use(cors());

app.use(express.json());
app.use("/api", userRouter);

app.use(bodyParser.json());
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

//============database connection===========//

mongoose.connect(process.env.DB_URL, {
  useNewUrlParser: true,
  useCreateIndex: true,
  useUnifiedTopology: true,
});
const connection = mongoose.connection;
connection.once("open", () => {
  console.log("Mongodb database connection established successfully !!");
});

//==============server port===========//
app.listen(process.env.PORT, (err) => {
  if (err) throw err;
  console.log(` my server is running on port number ${process.env.PORT}`);
});
