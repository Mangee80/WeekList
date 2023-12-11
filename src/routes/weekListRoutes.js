const express = require('express');
const weekListController = require('../controllers/weekListController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

router.get('/test', (req, res) => {
    res.send('Test route is working!');
});  

// Add Week List API
router.post('/', authMiddleware.isLoggedIn, weekListController.addWeekList);

// Update Task in WeekList API
router.patch('/:id/tasks/:taskId', authMiddleware.isLoggedIn, authMiddleware.canModifyWeekList, weekListController.updateTask);

// Delete Task in WeekList API
router.delete('/:id/tasks/:taskId', authMiddleware.isLoggedIn, authMiddleware.canModifyWeekList, weekListController.deleteTask);

// Get All Week Lists API
router.get('/', authMiddleware.isLoggedIn, weekListController.getAllWeekLists);

module.exports = router;
