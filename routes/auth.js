const { ensureAuth } = require("../validators/verifytoken");
const Users = require('../models/users');
const cloudinary = require('../middlewares/cloudinary');
const Joi = require('joi');
const { customAlphabet } = require('nanoid/non-secure');
const redisClient = require("../middlewares/redis");
const multer = require('multer');
const express = require('express');
const env = require('dotenv');
const bcrypt = require('bcryptjs');
const logger = require("../middlewares/logger");
const generalrateLimiterMiddleware = require("../middlewares/rateLimiters/genericLimiter");
const jwt = require('jsonwebtoken');
const { RateLimiterRedis } = require('rate-limiter-flexible');
const sendOTP = require("../middlewares/aws_sns");
const twilioSMS = require("../middlewares/twilioSMS");

const router = express.Router();

env.config();

const schema = Joi.object({
    email: Joi.string().required().email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }),
    first_name: Joi.string().required().max(20).min(3).regex(/^[A-Za-z]+$/).error(new Error("Invalid First Name")),
    last_name: Joi.string().required().max(20).min(3).regex(/^[A-Za-z]+$/).error(new Error("Invalid Last Name")),
    location: Joi.string().required(),
    contact: Joi.string().trim().regex(/^[0-9]{12,13}$/).error(new Error('Invalid Phone number')),
    avatar: Joi.string()
});
const loginschema = Joi.object({
    contact: Joi.string().required().min(13).max(14).error(new Error("Invalid Phone Number")),

});

const nanoid = customAlphabet('1234567890', 6)
const storage = multer.diskStorage({

    filename: function (req, file, cb) {
        cb(null, nanoid() + '-' + file.originalname)
    },
})
const uploads = multer({
    storage: storage, fileFilter: (req, file, cb) => {
        if (file.mimetype == "image/png" || file.mimetype == "image/jpg" || file.mimetype == "image/jpeg") {
            cb(null, true);
        } else {
            cb(null, false);
            return cb(new Error('Only .png, .jpg and .jpeg format allowed!'));
        }
    }
});
//SignUp
router.post('/users/create', uploads.single("avatar"), async (req, res) => {

    //validate data before adding a user
    try {
        const bodyerror = await schema.validateAsync(req.body);

        //check if email already exist in database

        const emailExist = await Users.findOne({ email: req.body.email });
        if (emailExist) {
            return res.status(400).json({ message: "Email already exist" });
        }

        //check if contact already exist in database

        const contactexist = await Users.findOne({ contact: req.body.contact });
        if (contactexist) {
            return res.status(400).json({ message: `Contact ${req.body.contact} already exist` })
        }

        //uploading image to cloudinary

        const file = req.file

        let result
        if (file) {
            result = await cloudinary.uploader.upload(file.path)
        };
        //create new user object after validation and hashing

        const user = new Users({
            email: req.body.email,
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            contact: req.body.contact,
            avatar: result ? result.secure_url : null,
            cloudinary_id: result ? result.public_id : null
        });
        //try to save user 

        await user.save().then(result => {
            const otp_code = nanoid();
            twilioSMS(`Welcome! your mobile verification code is: ${otp_code}. Mobile Number is: ${mobileno}`, req.body.contact)
            return res.status(200).json({ message: "Account registered successfully, Please proceed to Login" });
        });





    } catch (error) {
        logger.error(`${error.status || 500} - ${req.body.contact} - ${req.body.email} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
        return res.status(400).json({ message: error.message })
    }





});

const opts = {
    redis: redisClient,
    points: 5, // 5 points
    duration: 15 * 60, // Per 15 minutes
    blockDuration: 15 * 60, // block for 15 minutes if more than points consumed 
};

const rateLimiter = new RateLimiterRedis(opts);

router.post('/user/login', async (req, res) => {
    try {
         const {bodyError,value }= await loginschema.validateAsync(req.body)

            
                //check if contact  exist in database
                const user =await Users.findOne({ contact: req.body.contact });

                if (!user) {
                    res.status(400).json({ message: "Account doesn't not exist" })
                } else {
                    //send otp and save in the redis db
                    const otp_code = nanoid();
                    const redisField=`${user.contact}OTP`
                   await redisClient.set(redisField.toString(),otp_code.toString(),"EX",180,(err,result)=>{
                      
                            if(err){
                                return res.status(400).json({ message: err })
                            }
                            twilioSMS(`Hello ${user.first_name} your verification code is: ${otp_code}. Mobile Number is: ${user.contact}`, user.contact).then(reply=>{
                            return res.status(200).json(`Hello ${user.first_name} your verification code is: ${otp_code}. Mobile Number is: ${user.contact}`)
                        }).catch(e=>{return res.status(400).json({message:e})})
                        
                    })
                    
                }

    } catch (error) {
        res.status(400).json({ message: error.message })
    }
})
//verify otpcode and assign jwt
router.post("/user/otpverify", async (req, res) => {
    const otpCode = req.body.otp_code
    const contact = req.body.contact
    try {
        if (otpCode) {
            const user = await Users.findOne({ contact: contact });

            if (!user) {
                res.status(400).json({ message: "Account doesn't not exist" })
            } else {
                const string=`${contact}OTP`
                
                //compare code in redis with the ones sent
                await redisClient.get(string.toString(), (err, redisData) => {
                    if (err) { return logger.error(err) };
                    
                    if (redisData === null || redisData != otpCode) {
                        // Consume 1 point for each failed login attempt
                        rateLimiter.consume(req.socket.remoteAddress)
                            .then((data) => {
                                // Message to user
                                return res.status(400).json({ message: `Invalid Code, you have ${data.remainingPoints} attempts left, Please Login Again` });
                            })
                            .catch((rejRes) => {
                                // Blocked
                                const secBeforeNext = Math.ceil(rejRes.msBeforeNext / 60000) || 1;
                                logger.error(`LoggingIn alert: Contact: ${req.body.contact} on IP: ${req.socket.remoteAddress} is Chocking Me !!`)
                                return res.status(429).send(`Too Many Requests, Try to Login After ${String(secBeforeNext)} Minutes`);
                            });


                    } else {

                        //create and assign a token once code is verified

                        const token = jwt.sign({ _id: user._id, role: user.role }, process.env.TOKEN_SECRET, { expiresIn: 120 })


                        const refreshToken = jwt.sign({ _id: user._id, role: user.role }, process.env.REFRESH_TOKEN_SECRET,
                            { expiresIn: '1d' });

                        redisClient.set(user._id.toString(), JSON.stringify({ refreshToken: refreshToken }));

                        const userInfo = {
                            _id: user._id,
                            first_name: user.first_name,
                            last_name: user.last_name,
                            contact: user.contact,
                            avatar: user.avatar
                        }
                        res.header('token', token).json({ 'token': token, 'refreshToken': refreshToken, 'user': userInfo });
                    }
                })

            }
        } else {
            return res.status(400).json({ message: "Invalid request, Login again to get another code" })
        }
    } catch (error) {
        return res.status(400).json({ message: error.message })
    }



})

//Deleting a Cleint
router.delete("/user/delete/:id", ensureAuth, async (req, res) => {
    try {
        //Find user by Id
        const user = await Users.findById(req.params.id);
        if (!user) {
            res.status(400).json({ message: "User not found" })
        }
        //Delete image from cloudinary
        await cloudinary.uploader.destroy(user.cloudinary_id)
        //delete user from mongoDB
        await user.remove();
        res.status(200).json({ message: "Account Deleted successfully" })
    } catch (error) {
        logger.error(`${error.status || 500} - ${req.params.id} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);

    }
});

//Updating user profile
router.put("/user/update/:id", ensureAuth, async (req, res) => {

    try {
        const user = await Users.findById(req.params.id);

        const data = {
            username: req.body.username || user.username,
            avatar: req.body.avatar || user.avatar

        }
        await Users.findByIdAndUpdate(req.params.id, data);
        res.status(200).json({ message: "Data Updated Successfully" })
    } catch (error) {

        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
        res.status(400).json({ message: error.message })
    }
});



function createUsers(users) {
    const usersList = [];

    for (let i of users) {
        usersList.push({
            _id: i._id,
            contact: i.contact,
            email: i.email,
            username: i.username,
            avatar: i.avatar,
            role: i.role

        })
    }
    return usersList;
}
//fetch all users
router.get('/users/all', generalrateLimiterMiddleware, ensureAuth, async (req, res, next) => {

    try {
        //verify user using OTP

        //check data in redisStore
        await redisClient.get('users', (err, result) => {
            if (err) {
                return logger.error(err)
            }
            if (result !== null) {

                return res.status(200).json({ usersList: JSON.parse(result) })
            } else {
                //fetch for users from DB and cache it
                Users.find().sort({ createdAt: -1 }).then((data, err) => {//fetch all documents in a descending order using createdAt

                    if (data) {
                        const userList = createUsers(data)
                        redisClient.set("users", JSON.stringify(userList), 'ex', 15)
                        return res.status(200).json({ userList })
                    }
                    if (err) {
                        return logger.error(err)
                    }
                })


            }
        })


    } catch (error) {
        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
        return res.status(400).json({ message: error.message })
    }

});


//get a user
router.get('/user/:id', ensureAuth, async (req, res) => {
    try {
        const user = await Users.findById(req.params.id).select('-password') //will disregard return of password.
        return res.status(200).json({ user })

    } catch (error) {
        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    }


})


router.post('/users/logout', async (req, res) => {
    try {
        const user_id = req.body.user_id

        //remove refresh token
        await redisClient.del(user_id.toString(), (err, reply) => {
            if (err) {
                return res.status(400).json({ message: err })
            }
            return res.status(200).json({ message: "Logged out successfull" })
        });

        //blacklist the access token
        await redisClient.set("BL_" + user_id.toString(), 'token')

    } catch (error) {
        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    }

})
module.exports = router;