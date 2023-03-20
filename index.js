import express from "express";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import jwt from "jsonwebtoken";
import cors from "cors";
import auth from "./auth.js";

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));

// require database connection
import dbConnect from "./db/dbConnect.js";
//execute database connection
dbConnect();

import Users from "./db/userModel.js";

//Curb Cores Error by adding a header here

//register endpoint
app.post("/register", (request, response) => {            
    //ищем пользователя в модели базы данных UsersModel
    Users.findOne({ email: request.body.email}, (err, userExist) => 
    {
        //существующего пользователя удаляем из базы данных
        if (userExist != undefined)
        {
            Users.findOneAndDelete(
            {
                email: request.body.email
            },
            (err, doc) => {
            });
        }

        //hash the password   
        bcrypt.hash(request.body.password,10).then((hashedPassword) => {
            //create a new user instance and collect the data
            const user = new Users({
                email: request.body.email,
                password: hashedPassword
            });

            //save the new user
            user.save()
            //return success if the new user is added to the database successfully
            .then((result) => {
                response.status(201).send({
                    message: "User Created Successfully",
                    result
                })
            })
            //catch error if the new user wasn't added successfully to the database
            .catch((error) => {
                response.status(500).send({
                    message: "Error creating user",
                    error
                })
            })
        })
        //catch error if the password hash isn't successfull
        .catch((e) => {
            response.status(500).send({
                message: "Password was not hashed successfully",
                e
            })
        })
    });
})

//login endpoint
app.post("/login", (request, response) => {
    //check if email exists
    Users.findOne({email: request.body.email})
    //if email exists
    .then((user) => {
        //compare the password entered and the hashed password found
        bcrypt.compare(request.body.password, user.password)
        //if the passwords match
        .then((passwordCheck) => {
            //check if password matches
            if (!passwordCheck) {
                return response.status(400).send({
                    message: "Passwords does not match",
                    error
                })
            }

            //create JWT token
            const token = jwt.sign(
                {
                    userId: user._id,
                    userEmail: user.email
                },
                "RANDOM-TOKEN",
                {expiresIn: "24h"}
            );

            //return success response
            response.status(200).send({
                message: "Login Successful",
                email: user.email,
                token
            })
        })
        //catch error if password does not match
        .catch((error) => {
            response.status(400).send({
                message: "Passwords does not match",
                error
            })
        })
    })
    //catch error if email does not exist
    .catch((e) => {
        response.status(404).send({
            message: "Email not found",
            e
        })
    })
})

//free endpoint
app.get("/free-endpoint", (_, response) => {
    response.json({message: "You are free to access me anytime"});
});

//authentication endpoint
app.get("/auth-endpoint", auth, (_, response) => {
    response.json({message: "You are authorized to access me"});
})

//запускаем сервер по порту 3001
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`))