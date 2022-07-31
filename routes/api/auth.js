const express = require("express");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const path = require("path");
const fs = require("fs/promises");

const { nanoid } = require("nanoid");

require("dotenv").config();

const User = require("../../models/user");

const { createError, sendMail } = require("../../helpers");
const { authorize, upload } = require("../../middlewares");

const router = express.Router();

const emailRegexp = /[a-z0-9]+@[a-z]+\.[a-z]{2,3}/;

const authRegisterSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().pattern(emailRegexp).required(),
  password: Joi.string().min(6).required(),
});

const authLoginSchema = Joi.object({
  email: Joi.string().pattern(emailRegexp).required(),
  password: Joi.string().min(6).required(),
});

const verifyEmailSchema = Joi.object({
  email: Joi.string().pattern(emailRegexp).required(),
});

const { SECRET_KEY } = process.env;

router.post("/signup", async (req, res, next) => {
  try {
    const { error } = authRegisterSchema.validate(req.body);

    if (error) {
      throw createError(400);
    }
    const { email, password, name } = req.body;

    const user = await User.findOne({ email });

    if (user) {
      throw createError(409, "Email in use");
    }
    const verificationToken = nanoid();

    const hashPassword = await bcrypt.hash(password, 10);
    const newAvatar = gravatar.url(email);
    const result = await User.create({
      email,
      password: hashPassword,
      name,
      avatarURL: newAvatar,
      verificationToken,
    });

    const mail = {
      to: email,
      subject: "Prove your email",
      html: `<a target="_blank" href="http://localhost:3000/api/auth/${verificationToken}> Press here to confirm your email"</a>`,
    };

    await sendMail(mail);

    res.status(201).json({
      name: result.name,
      email: result.email,
    });
  } catch (error) {
    next(error);
  }
});

router.get("/verify/:verificationToken", async (req, res, next) => {
  try {
    const { verificationToken } = req.params;

    const user = await User.findOne({ verificationToken });

    if (!user) {
      throw createError(404, "Not Found");
    }

    await User.findByIdAndUpdate(user._id, {
      verificationToken: "",
      verify: true,
    });

    res.json({ message: "Verification successful" });
  } catch (error) {
    next(error);
  }
});

router.post("/verify", async (req, res, next) => {
  try {
    const { error } = verifyEmailSchema.validate(req.body);

    if (error) {
      throw createError(400);
    }

    const { email } = req.body;

    const user = User.findOne({ email });

    if (!user) {
      throw createError(404);
    }

    if (user.verify) {
      throw createError(400, "Verification has already been passed");
    }

    const mail = {
      to: email,
      subject: "Prove your email",
      html: `<a target="_blank" href="http://localhost:3000/api/auth/${user.verificationToken}> Press here to confirm your email"</a>`,
    };

    await sendMail(mail);

    res.json({
      message: "Verification email sent",
    });
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { error } = authLoginSchema.validate(req.body);
    if (error) {
      throw createError(400);
    }
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    const passwordCompare = await bcrypt.compare(password, user.password);
    if (!user || !passwordCompare) {
      throw createError(401, "Email or password is wrong");
    }

    if (!user.verify) {
      throw createError(401, "Email not verify");
    }

    const payload = {
      id: user._id,
    };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });

    await User.findByIdAndUpdate(user._id, { token });
    res.json({
      token,
    });
  } catch (error) {
    next(error);
  }
});

router.get("/logout", authorize, async (req, res, next) => {
  try {
    const { _id } = req.user;
    await User.findByIdAndUpdate(_id, { token: null });
    res.json({
      message: "Logout success",
    });
  } catch (error) {
    next(error);
  }
});

router.get("/current", authorize, async (req, res) => {
  const { name, email } = req.user;
  res.json({
    name,
    email,
  });
});

const avatarsDir = path.join(__dirname, "../../", "public", "avatars");
router.patch(
  "/avatars",
  authorize,
  upload.single("avatar"),
  async (req, res, next) => {
    try {
      const { _id } = req.user;
      const { path: tempDir, originalname } = req.file;
      const [extension] = originalname.split(".").reverse();
      const newAvatar = `${_id}.${extension}`;
      const uploadDir = path.join(avatarsDir, newAvatar);
      await fs.rename(tempDir, uploadDir);
      const avatarURL = path.join("avatars", newAvatar);
      await User.findByIdAndUpdate(req.user._id, { avatarURL });
      res.json({ avatarURL });
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
