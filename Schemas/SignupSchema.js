import mongoose from 'mongoose'

const SignupSchema = mongoose.Schema({
    name:{
        type:String,
        required:[true, "Name is required"],
        minLength:2
    },
    email: {
        type: String,  // Data type is String
        required: [true, "Email is required"],  // Email is a required field
        unique: true,  // Email must be unique across the collection
        match: [/\S+@\S+\.\S+/, "Please use a valid email address"],  // Regular expression to validate the email format
    },
    password:{
        type:String,
        required:true,
        minLength:[5, "Password should have more than 5 characters"],
    }
})

export default mongoose.model("Signup", SignupSchema)