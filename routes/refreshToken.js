const express = require('express');
const generalrateLimiterMiddleware = require('../middlewares/rateLimiters/genericLimiter');

const { verifyRefreshToken, ensureAuth } = require('../validators/verifytoken');



const router= express.Router();

router.post('/refresh',verifyRefreshToken)
router.post("/verify",ensureAuth);


module.exports= router;