import mongoose from 'mongoose';

const SignupSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, "Name is required"],
        minLength: 2
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        match: [/\S+@\S+\.\S+/, "Please use a valid email address"],
    },
    password: {
        type: String,
        required: true,
        minLength: [5, "Password should have more than 5 characters"],
    }
});

const Signup = mongoose.model("Signup", SignupSchema);

export default Signup;  // Default export
