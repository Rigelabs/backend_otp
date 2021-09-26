const {createLogger, format, transports, transport} =require('winston');
const SlackHook = require('winston-slack-webhook-transport');
require('winston-mongodb');


const env= require('dotenv');
env.config();

const MONGO_URI = process.env.WINSTON_MONGODB_URI;

module.exports = createLogger({
    transports:[

 // File transport
    new transports.File({
    filename: 'logs/winstonLogs.log',
    format:format.combine(
        format.timestamp({format: 'MMM-DD-YYYY HH:mm:ss'}),
        format.align(),
        format.printf(info => `${info.level}: ${[info.timestamp]}: ${info.message}`),
    )}),
    new transports.MongoDB({
        level:'info',
        db: MONGO_URI,
        options:{
            useUnifiedTopology:true
        },
        collection:'server_logs',
        tryReconnect:true,
        format:format.combine(
            format.timestamp(),
            //convert logs to a json format for mongodb
            format.json()
                )
    }),
    new SlackHook({
        webhookUrl:"https://hooks.slack.com/services/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"
    })
    ]
})