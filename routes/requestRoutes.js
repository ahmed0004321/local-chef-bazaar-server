const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { verifyFBToken } = require('../middlewares/auth');
const { collections } = require('../config/db');
const { requestCollections, userCollections } = collections;

router.post("/requests", async (req, res) => {
    const request = req.body;

    const existingRequest = await requestCollections.findOne({
        userEmail: request.userEmail,
        requestType: request.requestType,
        requestStatus: "pending"
    });

    if (existingRequest) {
        return res.status(409).send({ message: "A pending request of this type already exists." });
    }

    const newRequest = {
        ...request,
        requestStatus: "pending",
        requestTime: new Date(),
    };
    const result = await requestCollections.insertOne(newRequest);
    res.send(result);
});

router.get("/requests", verifyFBToken, async (req, res) => {
    const result = await requestCollections.find().toArray();
    res.send(result);
});

router.patch("/requests/:id", verifyFBToken, async (req, res) => {
    const id = req.params.id;
    const { status, userEmail, requestType } = req.body;

    try {
        const filter = { _id: new ObjectId(id) };
        const updateDoc = {
            $set: { requestStatus: status },
        };

        const result = await requestCollections.updateOne(filter, updateDoc);

        if (status === "approved" && result.modifiedCount > 0) {
            const userFilter = { email: userEmail };
            let userUpdateDoc = { $set: { role: requestType } };

            if (requestType === "chef") {
                const randomNum = Math.floor(1000 + Math.random() * 9000);
                const chefId = `chef-${randomNum}`;
                userUpdateDoc.$set.chefId = chefId;
            }

            await userCollections.updateOne(userFilter, userUpdateDoc);
        }

        res.send(result);
    } catch (error) {
        console.error("Error updating request:", error);
        res.status(500).send({ message: "Failed to update request" });
    }
});

module.exports = router;
