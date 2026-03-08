const express = require('express');
const router = express.Router();
const { collections } = require('../config/db');
const { subscriberCollections } = collections;

router.post("/subscribers", async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).send({ message: "Email is required" });
        }

        const existing = await subscriberCollections.findOne({ email });
        if (existing) {
            return res.status(400).send({ message: "You are already subscribed!" });
        }

        const result = await subscriberCollections.insertOne({
            email,
            subscribedAt: new Date(),
        });
        res.send(result);
    } catch (error) {
        console.error("Error subscribing:", error);
        res.status(500).send({ message: "Failed to subscribe" });
    }
});

module.exports = router;
