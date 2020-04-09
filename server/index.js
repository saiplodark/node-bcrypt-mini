require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

massive(CONNECTION_STRING).then(db => {
  console.log('connected to db')
  app.set('db', db);
});

app.post('/auth/signup', (req, res, next) => {
  const { email, password } = req.body;
  const db = req.app.get('db');
  db.check_user_exists(email).then( user => {
    if(user.length) {
      res.status(400).send('email already exists in database')
    }
    const saltRounds = 12;
    bcrypt.genSalt(saltRounds).then( salt => {
      bcrypt.hash(password, salt).then( hashedPassword => {
        db.create_user([email, hashedPassword]).then(createdUser => {
          req.session.user = {
            id: createdUser[0].id,
            email: createdUser[0].email
          }
          res.status(200).send(req.session.user);
        })
      })
    })
  })
})

app.post('/auth/login', (req, res, next) => {
  const { email, password } = req.body;
  const db = req.app.get('db');
  db.check_user_exists(email).then( user => {
    if(!user.length){
      res.status(400).send('User does not exist')
    } else {
      bcrypt.compare(password, user[0].user_password).then(isAuthenticated => {
        if(isAuthenticated){
          req.session.user = {
            id: user[0].id,
            email: user[0].email
          }
          res.status(200).send(req.session.user)
        } else {
          res.status(400).send('that is the incorrect email/password')
        }
      })
    }
  })
})

app.get('/auth/logout', (req,res)=>{
  req.session.destroy();
  res.sendStatus(200)
})

app.get('/auth/user',(req, res)=>{
  if(req.session.user){
  res.status(200).send(req.session.user)
  }else{
    res.status(404).send('uesr not found')
  }
})

app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
