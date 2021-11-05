const env = require('dotenv');
const logger = require('./logger');
env.config();


const credentials= {
    apiKey: process.env.AFRICAS_TALKING_APIKEY,
    username: process.env.AFRICAS_TALKING_USERNAME
}
async function AT_Sms(to,message){
    const AfricaTalking= require('africastalking')(credentials)

    const sms = AfricaTalking.SMS

    //send sms
    const options = {
        to:to,
        message:message,
        shortCode:"5106",
        keyword:"xxxxx",
        retryDurationInHours: 12
    }
    sms.sendPremium(options).then(res=>{
       return(console.log(res),logger.info(res))
    })
    .catch(err=>{
       return(console.log(err), logger.error(err))
    })
}

module.exports = AT_Sms;