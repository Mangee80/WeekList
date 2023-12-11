const WeekList = require('../models/WeekList');

// Add Week List API
exports.addWeekList = async (req, res) => {
  try {
    const { description } = req.body;
    const userWeekLists = await WeekList.find({ userId: req.user._id, locked: false });

    if (userWeekLists.length < 2) {
      const newWeekList = await WeekList.create({ userId: req.user._id, description });
      res.json({
        status: 'SUCCESS',
        message: 'Week list created successfully',
        data: newWeekList
      });
    } else {
      res.json({
        status: 'FAILED',
        message: 'You can have only two active week lists at a time. Wait for one to end.'
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

// Update Task in WeekList API
exports.updateTask = async (req, res) => {
  try {
    const { id, taskId } = req.params;
    const { task, isCompleted } = req.body;

    // Find the task in the weeklist and update it
    const taskToUpdate = req.weekList.description.find(task => task._id.toString() === taskId);

    if (!taskToUpdate) {
      return res.status(404).json({ status: 'FAILED', message: 'Task not found' });
    }

    taskToUpdate.task = task || taskToUpdate.task;
    taskToUpdate.isCompleted = isCompleted !== undefined ? isCompleted : taskToUpdate.isCompleted;

    await req.weekList.save();

    // Check if all tasks are marked as completed
    const allTasksCompleted = req.weekList.description.every(task => task.isCompleted);

    // If all tasks are completed, mark the weeklist as complete
    if (allTasksCompleted) {
      req.weekList.locked = true;
      await req.weekList.save();
    }

    res.json({
      status: 'SUCCESS',
      message: 'Task updated successfully',
      data: req.weekList
    });
  } catch (error) {
    console.log(error);
    res.json({
      status: 'FAILED',
      message: 'Something went wrong'
    });
  }
};

// Delete Task in WeekList API
exports.deleteTask = async (req, res) => {
  try {
    const { id, taskId } = req.params;

    // Find and remove the task from the weeklist
    const taskIndex = req.weekList.description.findIndex(task => task._id.toString() === taskId);

    if (taskIndex === -1) {
      return res.status(404).json({ status: 'FAILED', message: 'Task not found' });
    }

    req.weekList.description.splice(taskIndex, 1);

    await req.weekList.save();

    // Check if all tasks are marked as completed
    const allTasksCompleted = req.weekList.description.every(task => task.isCompleted);

    // If all tasks are completed, mark the weeklist as complete
    if (allTasksCompleted) {
      req.weekList.locked = true;
      await req.weekList.save();
    }

    res.json({
      status: 'SUCCESS',
      message: 'Task deleted successfully',
      data: req.weekList
    });
  } catch (error) {
    console.log(error);
    res.json({
      status: 'FAILED',
      message: 'Something went wrong'
    });
  }
};

// Get All Week Lists API
exports.getAllWeekLists = async (req, res) => {
  try {
    const weekLists = await WeekList.find({ userId: req.user._id });
    const currentTime = new Date();
    const weekListsInfo = weekLists.map(weekList => {
      const timeLeft = weekList.locked ? 0 : Math.max(0, (weekList.createdAt.getTime() + (7 * 24 * 60 * 60 * 1000) - currentTime.getTime()) / 1000);
      return { ...weekList._doc, timeLeft };
    });
    res.json({
      status: 'SUCCESS',
      data: weekListsInfo
    });
  } catch (error) {
    console.log(error);
    res.json({
      status: 'FAILED',
      message: 'Something went wrong'
    });
  }
};
