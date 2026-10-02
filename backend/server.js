require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("./db");

const app = express();


// =========================
// MIDDLEWARE
// =========================

app.use(cors());
app.use(express.json());


// =========================
// HOME ROUTE
// =========================

app.get("/", (req, res) => {
    res.json({
        message: "Server is working!"
    });
});


// =========================
// SIGNUP ROUTE
// =========================

app.post("/signup", async (req, res) => {

    try {

        const { name, email, password } = req.body;


        // Check all fields
        if (!name || !email || !password) {

            return res.status(400).json({
                message: "Please fill all fields"
            });

        }


        // Check if email already exists

        const checkUserSql =
            "SELECT * FROM users WHERE email = ?";


        db.query(
            checkUserSql,
            [email],
            async (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        message: "Database error"
                    });

                }


                // Email already exists

                if (results.length > 0) {

                    return res.status(400).json({
                        message: "Email already registered"
                    });

                }


                // Hash password

                const hashedPassword =
                    await bcrypt.hash(password, 10);


                // Insert user

                const insertUserSql =
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";


                db.query(
                    insertUserSql,
                    [name, email, hashedPassword],
                    (err, result) => {

                        if (err) {

                            console.log(err);

                            return res.status(500).json({
                                message: "User registration failed"
                            });

                        }


                        // Signup successful

                        res.status(201).json({
                            message: "Signup successful!",
                            userId: result.insertId
                        });

                    }
                );

            }
        );

    } catch (error) {

        console.log(error);

        res.status(500).json({
            message: "Something went wrong"
        });

    }

});


// =========================
// LOGIN ROUTE
// =========================

app.post("/login", async (req, res) => {

    try {

        const { email, password } = req.body;


        // Check email and password

        if (!email || !password) {

            return res.status(400).json({
                message: "Please enter email and password"
            });

        }


        // Find user by email

        const sql =
            "SELECT * FROM users WHERE email = ?";


        db.query(
            sql,
            [email],
            async (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        message: "Database error"
                    });

                }


                // User not found

                if (results.length === 0) {

                    return res.status(401).json({
                        message: "Invalid email or password"
                    });

                }


                // User found

                const user = results[0];


                // Check password

                const passwordMatch =
                    await bcrypt.compare(
                        password,
                        user.password
                    );


                // Wrong password

                if (!passwordMatch) {

                    return res.status(401).json({
                        message: "Invalid email or password"
                    });

                }


                // =========================
                // CREATE JWT TOKEN
                // =========================

                const token = jwt.sign(
                    {
                        id: user.id,
                        email: user.email
                    },
                    process.env.JWT_SECRET,
                    {
                        expiresIn: "1d"
                    }
                );


                // Login successful

                res.json({
                    message: "Login successful!",
                    token: token,
                    user: {
                        id: user.id,
                        name: user.name,
                        email: user.email
                    }
                });

            }
        );

    } catch (error) {

        console.log(error);

        res.status(500).json({
            message: "Something went wrong"
        });

    }

});


// =========================
// JWT AUTHENTICATION MIDDLEWARE
// =========================

const authenticateToken = (req, res, next) => {

    try {

        // Get Authorization header

        const authHeader =
            req.headers["authorization"];


        // Check if Authorization header exists

        if (!authHeader) {

            return res.status(401).json({
                message: "Access denied. Token is required."
            });

        }


        // Expected format:
        // Bearer YOUR_TOKEN

        const token =
            authHeader.split(" ")[1];


        // Check token

        if (!token) {

            return res.status(401).json({
                message: "Invalid token format"
            });

        }


        // Verify token

        const decoded =
            jwt.verify(
                token,
                process.env.JWT_SECRET
            );


        // Save decoded user information

        req.user = decoded;


        // Continue to protected route

        next();

    } catch (error) {

        console.log(
            "JWT verification error:",
            error.message
        );

        return res.status(401).json({
            message: "Invalid or expired token"
        });

    }

};


// =========================
// PROTECTED PROFILE ROUTE
// =========================

app.get(
    "/profile",
    authenticateToken,
    (req, res) => {

        // Get user ID from JWT

        const userId = req.user.id;


        // Get user from database

        const sql =
            "SELECT id, name, email, created_at FROM users WHERE id = ?";


        db.query(
            sql,
            [userId],
            (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        message: "Database error"
                    });

                }


                // User not found

                if (results.length === 0) {

                    return res.status(404).json({
                        message: "User not found"
                    });

                }


                // Profile successful

                res.json({
                    message: "Profile fetched successfully!",
                    user: results[0]
                });

            }
        );

    }
);


// =========================
// START SERVER
// =========================

app.listen(5000, () => {

    console.log(
        "🚀 Server started on port 5000"
    );

});