import mongoose from "mongoose";
const SigninSchema = mongoose.Schema({
    email:{
        type:String,
        required:[true, "Email is required"],
        unique:true,
        match: [/\S+@\S+\.\S+/, "Please use a valid email address"]
    }
})

export default mongoose.model("Signin", SigninSchema)