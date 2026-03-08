const express = require('express');
const router = express.Router();
const bcrypt = require("bcryptjs");
const { ObjectId } = require('mongodb');
const { verifyFBToken } = require('../middlewares/auth');
const { collections } = require('../config/db');
const { userCollections, orderCollections } = collections;

router.get("/myProfile", async (req, res) => {
    const email = req.query.email;
    if (!email) {
        return res.status(400).json({ error: "Email is required" });
    }

    try {
        const user = await userCollections.findOne({ email: email });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

router.post("/users", async (req, res) => {
    const user = req.body;
    const email = user?.email;

    const userExists = await userCollections.findOne({ email });
    if (userExists) {
        const updateDoc = {};
        if (user.displayName && user.displayName !== userExists.displayName) {
            updateDoc.displayName = user.displayName;
        }
        if (user.photoURL && user.photoURL !== userExists.photoURL) {
            updateDoc.photoURL = user.photoURL;
        }

        if (Object.keys(updateDoc).length > 0) {
            await userCollections.updateOne({ email }, { $set: updateDoc });
            const updatedUser = await userCollections.findOne({ email });
            return res.send(updatedUser);
        }
        return res.send(userExists);
    }

    const newUser = {
        ...user,
        role: "customer",
        status: "active",
        created_at: new Date(),
    };

    if (user.password) {
        const salt = await bcrypt.genSalt(10);
        newUser.passwordHash = await bcrypt.hash(user.password, salt);
        delete newUser.password;
    }

    await userCollections.insertOne(newUser);
    res.send(newUser);
});

router.post("/users/login-verify", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send({ message: "Email and password are required" });
    }

    const user = await userCollections.findOne({ email });
    if (!user || !user.passwordHash) {
        return res.status(404).send({ message: "User not found or no password registered" });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (isMatch) {
        res.send({ success: true, message: "Password verified professionally!" });
    } else {
        res.status(401).send({ success: false, message: "Invalid credentials" });
    }
});

router.patch("/users/settings", verifyFBToken, async (req, res) => {
    try {
        const email = req.decoded_email;
        const settings = req.body;

        const result = await userCollections.updateOne(
            { email },
            { $set: { settings } },
            { upsert: true }
        );
        res.send(result);
    } catch (error) {
        console.error("Error updating settings:", error);
        res.status(500).send({ message: "Failed to update settings" });
    }
});

router.patch("/users/change-password", verifyFBToken, async (req, res) => {
    try {
        const email = req.decoded_email;
        const { currentPassword, newPassword } = req.body;

        const user = await userCollections.findOne({ email });
        if (!user || !user.passwordHash) {
            return res.status(404).send({ message: "User not found or no password set" });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!isMatch) {
            return res.status(401).send({ message: "Incorrect current password" });
        }

        const salt = await bcrypt.genSalt(10);
        const newPasswordHash = await bcrypt.hash(newPassword, salt);

        const result = await userCollections.updateOne(
            { email },
            { $set: { passwordHash: newPasswordHash } }
        );
        res.send(result);
    } catch (error) {
        console.error("Error changing password:", error);
        res.status(500).send({ message: "Failed to change password" });
    }
});

router.get("/users/admin", verifyFBToken, async (req, res) => {
    try {
        const result = await userCollections.aggregate([
            {
                $lookup: {
                    from: "myOrders",
                    localField: "email",
                    foreignField: "userEmail",
                    as: "orders"
                }
            },
            {
                $addFields: {
                    ordersCount: { $size: "$orders" },
                    totalSpent: {
                        $reduce: {
                            input: "$orders",
                            initialValue: 0,
                            in: {
                                $add: [
                                    "$$value",
                                    {
                                        $cond: [
                                            { $eq: ["$$this.paymentStatus", "paid"] },
                                            { $toDouble: { $ifNull: ["$$this.price", 0] } },
                                            0
                                        ]
                                    }
                                ]
                            }
                        }
                    },
                    lastOrder: { $arrayElemAt: ["$orders.created_at", -1] }
                }
            },
            {
                $project: {
                    orders: 0
                }
            }
        ]).toArray();
        res.send(result);
    } catch (error) {
        console.error("Error fetching users for admin:", error);
        res.status(500).send({ message: "Internal Server Error" });
    }
});

router.patch("/users/fraud/:id", verifyFBToken, async (req, res) => {
    const id = req.params.id;
    const filter = { _id: new ObjectId(id) };
    const updateDoc = {
        $set: {
            status: "fraud",
        },
    };
    const result = await userCollections.updateOne(filter, updateDoc);
    res.send(result);
});

router.patch("/users/bulk-fraud", verifyFBToken, async (req, res) => {
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids)) {
        return res.status(400).send({ message: "Invalid IDs" });
    }
    const filter = { _id: { $in: ids.map(id => new ObjectId(id)) } };
    const updateDoc = { $set: { status: "fraud" } };
    const result = await userCollections.updateMany(filter, updateDoc);
    res.send(result);
});

router.delete("/users/bulk-delete", verifyFBToken, async (req, res) => {
    const { ids } = req.body;
    if (!ids || !Array.isArray(ids)) {
        return res.status(400).send({ message: "Invalid IDs" });
    }
    const filter = { _id: { $in: ids.map(id => new ObjectId(id)) } };
    const result = await userCollections.deleteMany(filter);
    res.send(result);
});

router.patch("/users/:id", verifyFBToken, async (req, res) => {
    const id = req.params.id;
    const updateData = req.body;
    const filter = { _id: new ObjectId(id) };

    delete updateData._id;

    const updateDoc = { $set: updateData };
    const result = await userCollections.updateOne(filter, updateDoc);
    res.send(result);
});

router.patch("/dashboard/manageUserRoleFraud/:id", async (req, res) => {
    const userId = req.params.id;
    const result = await userCollections.updateOne(
        { _id: new ObjectId(userId) },
        { $set: { status: "fraud" } },
    );
    res.send(result);
});

router.get("/dashboard/countUser", async (req, res) => {
    const result = await userCollections.find().toArray();
    res.send(result);
});

module.exports = router;
