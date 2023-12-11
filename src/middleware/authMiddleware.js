const jwt = require('jsonwebtoken');
const WeekList = require('../models/WeekList');

// Check if user is logged in
exports.isLoggedIn = (req, res, next) => {
  try {
    const { jwttoken } = req.headers;
    const user = jwt.verify(jwttoken, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (error) {
    console.log(error);
    res.json({
      status: 'FAILED',
      message: "You've not logged in! Please login"
    });
  }
};

// Check if user can modify the week list
exports.canModifyWeekList = async (req, res, next) => {
  try {
    const weekList = await WeekList.findById(req.params.id);
    if (weekList.userId.equals(req.user._id) && !weekList.locked) {
      req.weekList = weekList; // Attach the weeklist to the request object for further use
      next();
    } else {
      res.json({
        status: 'FAILED',
        message: "You don't have permission to modify this week list"
      });
    }
  } catch (error) {
    console.log(error);
    res.json({
      status: 'FAILED',
      message: 'Something went wrong'
    });
  }
};
