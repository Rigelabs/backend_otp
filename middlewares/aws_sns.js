const AWS = require('aws-sdk');
const { customAlphabet } = require('nanoid/non-secure');
const env = require('dotenv');
const redisClient = require('./redis');
const logger = require('./logger');
env.config();

const nanoid = customAlphabet('1234567890ABCDEF', 6)

const SNS_Client = new AWS.SNS({ region: process.env.AWS_REGION,
                                    credentials:({
                                        accessKeyId:process.env.AWS_ACCESS_KEY_ID,
                                        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
                                    }),
                                   
                                })

async function sendOTP(mobileno) {
    
    const otp_code = nanoid();

    const params = {
        Message: `Welcome! your mobile verification code is: ${otp_code}. Mobile Number is: ${mobileno}`,
        PhoneNumber: mobileno,
        //TopicArn:process.env.TOPICARN,
    };
  
    try {
        SNS_Client.publish(params, (err,data)=>{
            if(data){
                redisClient.set(mobileno.toString(),JSON.stringify({redisCode:otp_code}),'EXP',60,(err,result)=>{
                    if(err) return logger.error(err)
                    
                })
                return console.log("OTP sent", data)
            }
           if(err) return console.log(err)
        });
       
    } catch (err) {
            return console.log(err.stack)
    
    }
   
    
}

module.exports = sendOTP;
