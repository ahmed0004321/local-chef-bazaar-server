const express = require('express');
const router = express.Router();
const { verifyFBToken } = require('../middlewares/auth');
const { collections } = require('../config/db');
const { complaintCollections, userCollections } = collections;

router.post("/complaints", async (req, res) => {
    try {
        const complaint = req.body;
        const result = await complaintCollections.insertOne({
            ...complaint,
            status: "pending",
            createdAt: new Date(),
        });
        res.send(result);
    } catch (error) {
        console.error("Error submitting complaint:", error);
        res.status(500).send({ message: "Failed to submit complaint" });
    }
});

router.get("/complaints", verifyFBToken, async (req, res) => {
    try {
        const userEmail = req.decoded_email;
        const user = await userCollections.findOne({ email: userEmail });
        if (user?.role !== "admin") {
            return res.status(403).send({ message: "forbidden access" });
        }
        const result = await complaintCollections
            .find()
            .sort({ createdAt: -1 })
            .toArray();
        res.send(result);
    } catch (error) {
        console.error("Error fetching complaints:", error);
        res.status(500).send({ message: "Failed to fetch complaints" });
    }
});

module.exports = router;
