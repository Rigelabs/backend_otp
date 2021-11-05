const { RateLimiterRedis } = require('rate-limiter-flexible');
const AT_Sms = require('../africaTalking');

const logger = require('../logger');
const redisClient = require('../redis');
const twilioSMS = require('../twilioSMS');


const opts = {
  redis: redisClient,
  keyPrefix: 'generic_fail_ip_per_day',
    points: 10,// number of points
    duration: 60,//per 60seconds
    blockDuration: 60*60, // Block for 1 hr, if all points are consumed in 1 minute
   
};

const rateLimiterRedis = new RateLimiterRedis(opts);

const generalrateLimiterMiddleware = (req, res, next) => {
      rateLimiterRedis.consume(req.connection.remoteAddress)
        .then((rateLimiterRes) => {
         next();
         })
          .catch((rejRes) => {
            if(rejRes instanceof Error){
              logger.error("Redis Error in Generic limiter", rejRes)
            }else{
              res.status(429).json({message:'Too Many Requests'});
            const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
            //AT_Sms(process.env.AFRICAS_TALKING_PHONE_NUMBER,` Retry-After - ${String(secs)} Seconds - ${res.statusMessage}-${rejRes.status || 429} - ${req.originalUrl} - ${req.method} - ${req.ip}`)
            twilioSMS(` Retry-After - ${String(secs)} Seconds - ${res.statusMessage}-${rejRes.status || 429} - ${req.originalUrl} - ${req.method} - ${req.ip}`,"+254720422288")
            logger.warn(`Too Many Requests. Retry-After - ${String(secs)} Seconds - ${res.statusMessage}-${rejRes.status || 429} - ${req.originalUrl} - ${req.method} - ${req.ip}`)
            }
          });
  
          
      };

module.exports =generalrateLimiterMiddleware;