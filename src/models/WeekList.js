const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
  task: String,
  isCompleted: Boolean
});

const weekListSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Types.ObjectId,
    ref: 'User'
  },
  description: [taskSchema],
  createdAt: { type: Date, default: Date.now },
  locked: { type: Boolean, default: false }
});

const WeekList = mongoose.model('WeekList', weekListSchema);

module.exports = WeekList;
