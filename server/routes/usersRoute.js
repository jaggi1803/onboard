const router = require("express").Router();
const User = require("../models/usersModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require('nodemailer');
const authMiddleware = require("../middlewares/authMiddleware")

//register user account

// new user registration
router.post("/register", async (req, res) => {
  try {
    // check if user already exists
    const user = await User.findOne({ email: req.body.email });
    if (user) {
      throw new Error("User already exists");
    }

    // hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    req.body.password = hashedPassword;

    // save user
    const newUser = new User(req.body);
    await newUser.save();
    res.send({
      success: true,
      message: "User created successfully",
    });
  } catch (error) {
    res.send({
      success: false,
      message: error.message,
    });
  }
});

// user login
router.post("/login", async (req, res) => {
  try {
    // check if user exists
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      throw new Error("User not found");
    }

    // if user is active
    // if (user.status !== "active") {
    //   throw new Error("The user account is inactive or suspended , please contact admin");
    // }

    // compare password
    const validPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!validPassword) {
      throw new Error("Invalid password");
    }

    // create and assign token
    const token = jwt.sign({ userId: user._id }, process.env.jwt_secret, {
      expiresIn: "1d",
    });

    // send response
    res.send({
      success: true,
      message: "User logged in successfully",
      data: token,
    });
  } catch (error) {
    res.send({
      success: false,
      message: error.message,
    });
  }
});

//get user info
router.post("/get-user-info", authMiddleware, async (req, res) => {
  try {

    const user = await User.findById(req.body.userId);
    user.password = ''

    res.send({
      message: "User info fetched successfully",
      data: user,
      success: true,
    })

  } catch (error) {
    res.send({
      message: error.message,
      success: false,
    })

  }
})

// get all users
router.get("/get-users", authMiddleware, async (req, res) => {
  try {
    const users = await User.find();
    res.send({
      success: true,
      message: "Users fetched successfully",
      data: users,
    });
  } catch (error) {
    res.send({
      success: false,
      message: error.message,
    });
  }
});



// Send email
router.post('/send-email',authMiddleware, async (req, res) => {
  try {
    const { email, subject, html } = req.body;

    // Create a Nodemailer transporter using SMTP transport
    let transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    // Define email options
    let mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: subject || 'Your Subject Here',
      html: html || '<p>Your custom HTML email template here</p>',
    };

    // Send email
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Email sent successfully' });
  } catch (error) {
    console.error('Error sending email:', error);
    res.status(500).json({ error: 'An error occurred while sending the email' });
  }
});

module.exports = router;
