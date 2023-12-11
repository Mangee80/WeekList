const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.signup = async (req, res) => {
  try {
    const { fullname, email, password, age, gender, mobile } = req.body;
    const encryptedPassword = await bcrypt.hash(password, 10);
    await User.create({ fullname, email, password: encryptedPassword, age, gender, mobile });
    res.json({
      status: 'SUCCESS',
      message: "You've signed up successfully!"
    });
  } catch (error) {
    console.log(error);
    res.json({
      status: 'FAILED',
      message: 'Something went wrong'
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      const hasPasswordMatched = await bcrypt.compare(password, user.password);
      if (hasPasswordMatched) {
        const jwtToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET, { expiresIn: 60 * 30 });
        res.json({
          status: 'SUCCESS',
          message: "You've logged in successfully!",
          jwtToken
        });
      } else {
        res.json({
          status: 'FAILED',
          message: 'Incorrect credentials! Please try again'
        });
      }
    } else {
      res.json({
        status: 'FAILED',
        message: 'User does not exist'
      });
    }
  } catch (error) {
    console.log(error);
    res.json({
      status: 'FAILED',
      message: 'Incorrect credentials! Please try again'
    });
  }
};
