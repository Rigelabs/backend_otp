const mongoose=require('mongoose')

const userSchema=new mongoose.Schema({
 
    first_name:{
        type:String,
        required:true,
    },
    contact:{
        type:String,
        required:true,
        unique:true
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
   
    last_name: {
        type: String,
        required: true,
    },
    avatar:{
        type:String
    },
    cloudinary_id:{
        type:String
    },
    
},{timestamps:true})



module.exports=mongoose.model('User',userSchema);