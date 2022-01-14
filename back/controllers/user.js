const bcrypt    = require("bcrypt");
const jwt       = require("jsonwebtoken");
const User      = require("../models/User");
const Joi       = require("joi");
const passwordValidator = require('password-validator');
const dotenv    = require('dotenv').config();

// Schema for password strength
const pvSchema = new passwordValidator();
pvSchema
    .is().min(8)                                                     // Minimum length 8
    .is().max(100)                                                   // Maximum length 100
    .has().uppercase()                                               // Must have uppercase letters
    .has().lowercase()                                               // Must have lowercase letters
    .has().digits()                                                  // Must have digits
    .has().not().spaces()                                            // Should not have spaces
    .is().not().oneOf(['Passw0rd', 'Password123', 'Motdepasse123']); // Blacklist these values

exports.signup = (req, res, next) => {
    // Checks the validity of the data entered during the connection.
    const schema = Joi.object().keys({
        email: Joi.string().regex(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,10})+$/).required(),
        password: Joi.string().min(3).required()
    })
    if (schema.validate(req.body).error) {
        res.send(schema.validate(req.body).error.details)
    } else if(pvSchema.validate(req.body.password) !== true) { // Checks password strength
        res.status(422).json({ message: "Password too weak." })
    } else {
    bcrypt.hash(req.body.password, 10)
        .then(hash => {        
            const user = new User({
                email: req.body.email,
                password: hash
            });
            user.save()
                .then(() => res.status(201).json({ message: "User created." }))
                .catch(error => res.status(400).json({ error }));
        
        })
        .catch(error => res.status(500).json({ error }))
    }
};

exports.login = (req, res, next) => {
    User.findOne({ email: req.body.email })
        .then(user => {
            if (!user) {
                return res.status(401).json({ error: "User not found." });
            }
            bcrypt.compare(req.body.password, user.password)
                .then(valid => {
                    if (!valid) {
                        return res.status(401).json({ error: "Incorrect password." });
                    }
                    res.status(200).json({
                        userId: user._id,
                        token: jwt.sign(
                            { userId: user._id },
                            process.env.DB_KEY,
                            { expiresIn: "24h" }
                        )
                    });
                })
                .catch(error => res.status(500).json({ error }));
        })
        .catch(error => res.status(500).json({ error }));
};