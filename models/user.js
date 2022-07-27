const { Schema, model } = require("mongoose");
const emailRegexp = /[a-z0-9]+@[a-z]+\.[a-z]{2,3}/;
const userSchema = Schema({
  name: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: [true, "Password is required"],
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    match: emailRegexp,
  },
  subscription: {
    type: String,
    enum: ["starter", "pro", "business"],
    default: "starter",
  },
  token: {
    type: String,
    default: null,
  },
  avatarURL: {
    type: String,
    required: true,
  },
});

const User = model("user", userSchema);

module.exports = User;
