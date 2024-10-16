const express = require("express");
require("express-async-errors");
const helmet = require("helmet");
const xss = require("xss-clean");
const rateLimiter = require("express-rate-limit");

require("dotenv").config(); //to access env variables

//routes
const secretWordRouter = require("./routes/secretWord");
const jobRouter = require("./routes/jobs");

const auth = require("./middleware/auth");

//to manage user sessions
const session = require("express-session");

const app = express();

// this section needs to go before routes
app.use((req, res, next) => {
  if (req.path == "/multiply") {
    res.set("Content-Type", "application/json");
  } else {
    res.set("Content-Type", "text/html");
  }
  next();
});

app.set("view engine", "ejs"); // tells express to use the ejs templating engine
app.use(require("body-parser").urlencoded({ extended: true }));

// uses mongodb to store session cookies data
const MongoDBStore = require("connect-mongodb-session")(session);

let mongoURL = process.env.MONGO_URI;
if (process.env.NODE_ENV == "test") {
  mongoURL = process.env.MONGO_URI_TEST;
}

// error check to make sure the MONGO_URI is defined
if (!mongoURL) {
  console.error("MONGO_URI is not defined in the environment variables.");
  process.exit(1);
}

const store = new MongoDBStore({
  // may throw an error, which won't be caught
  uri: mongoURL,
  collection: "mySessions",
});
store.on("error", function (error) {
  console.log("MongoDBStore error: ", error);
});

const sessionParms = {
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  store: store,
  cookie: { secure: false, sameSite: "strict" },
};

// if env is "production" then set secure cookies
if (app.get("env") === "production") {
  app.set("trust proxy", 1); // trust first proxy
  sessionParms.cookie.secure = true; // serve secure cookies
}

app.use(session(sessionParms));

//passport
const passport = require("passport");
const passportInit = require("./passport/passportInit");

passportInit();
app.use(passport.initialize());
app.use(passport.session());

app.use(require("connect-flash")());

app.use(require("./middleware/storeLocals"));
app.get("/", (req, res) => {
  res.render("index");
});

//CSRF
const csrf = require("host-csrf");
const cookieParser = require("cookie-parser");
app.use(cookieParser(process.env.SESSION_SECRET));
app.use(express.urlencoded({ extended: false }));
let csrf_development_mode = true;
if (app.get("env") === "production") {
  csrf_development_mode = false;
  app.set("trust proxy", 1);
}

app.set("trust proxy", 1);

app.use(helmet());
app.use(xss());

const csrf_options = {
  protected_operations: ["PATCH"],
  protected_content_types: ["application/json"],
  development_mode: csrf_development_mode,
};

app.use(csrf(csrf_options));
app.use(require("./middleware/storeLocals"));
app.get("/", (req, res) => {
  res.render("index");
});

app.use(require("./middleware/storeLocals"));
app.get("/", (req, res) => {
  res.render("index");
});

app.use("/sessions", require("./routes/sessionRoutes"));

app.use("/secretWord", require("./routes/secretWord"));

app.use("/jobs", auth, jobRouter);

// test multiple function
app.get("/multiply", (req, res) => {
  const result = req.query.first * req.query.second;
  if (result.isNaN) {
    result = "NaN";
  } else if (result == null) {
    result = "null";
  }
  res.json({ result: result });
});

app.use((req, res) => {
  res.status(404).send(`That page (${req.url}) was not found.`);
});

app.use((err, req, res, next) => {
  res.status(500).send(err.message);
  console.log(err);
});

const port = process.env.PORT || 3000;
const start = () => {
  try {
    require("./db/connect")(mongoURL);
    return app.listen(port, () =>
      console.log(`Server is listening on port ${port}...`)
    );
  } catch (error) {
    console.log(error);
  }
};

start();

module.exports = { app };
