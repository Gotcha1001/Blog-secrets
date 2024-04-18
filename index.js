import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/blogpost", isLoggedIn, (req, res) => {
  // Render the blogpost page
  res.render("blogpost.ejs");
});

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

app.post("/blogpost", isLoggedIn, async (req, res) => {
  if (!req.user) {
    // User is not authenticated, redirect to login page
    return res.redirect("/login");
  }

  const { title, content, picurl } = req.body;
  const { id: user_id } = req.user;

  try {
    const result = await db.query(
      "INSERT INTO blog_posts (title, content, date, picurl, user_id) VALUES ($1, $2, CURRENT_DATE, $3, $4) RETURNING *",
      [title, content, picurl, user_id]
    );
    const blogPost = result.rows[0];
    res.redirect("/blogpostdisplay"); // Redirect to the page displaying the blog post
  } catch (err) {
    console.log(err);
    res.status(500).send("Error creating blog post");
  }
});

app.get("/blogpostdisplay", async (req, res) => {
  try {
    // Fetch all blog posts from the database based on the user's ID
    const result = await db.query("SELECT * FROM blog_posts WHERE user_id = $1", [req.user.id]);
    const blogPosts = result.rows;

    // Render the blogpostdisplay page with the blog posts data
    res.render("blogpostdisplay.ejs", { blogPosts: blogPosts });
  } catch (err) {
    console.log(err);
    res.status(500).send("Error retrieving blog posts");
  }
});





//TODO: Create the post route for submit.
//Handle the submitted data and add it to the database

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/blogpost",
    failureRedirect: "/login",
  })
);


app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [username, email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/blogpost");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});





app.post("/login", passport.authenticate("local", {
  successRedirect: "/blogpost",
  failureRedirect: "/login",
 
}));





passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
     //   return cb(null, false); // User not found
     return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    //  return cb(err);
    }
  })
);


passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const email = profile.email;
        const username = email.split("@")[0]; // Using email as the username for simplicity
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
            [username, email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
