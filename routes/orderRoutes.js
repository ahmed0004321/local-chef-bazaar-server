const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { collections } = require('../config/db');
const { orderCollections, userCollections } = collections;

router.get('/dashboard/orderRequest/:id', async (req, res) => {
    const chefId = req.params.id;
    if (!chefId) {
        res.send({ massage: 'id not found' });
    }
    const result = await orderCollections.find({ chefId }).toArray();
    res.send(result);
});

router.patch("/dashboard/orderUpdate/:id", async (req, res) => {
    const { id } = req.params;
    const { status, paymentStatus } = req.body;

    const updateDoc = { $set: {} };
    if (status) updateDoc.$set.orderStatus = status;
    if (paymentStatus) updateDoc.$set.paymentStatus = paymentStatus;

    const result = await orderCollections.updateOne(
        { _id: new ObjectId(id) },
        updateDoc
    );

    res.send(result);
});

router.post("/myOrders", async (req, res) => {
    const orders = req.body;

    if (orders.userEmail) {
        const user = await userCollections.findOne({ email: orders.userEmail });
        if (user?.status === "fraud") {
            return res.status(403).send({ message: "Fraud users cannot place orders" });
        }
    }

    const myOrders = {
        ...orders,
        paymentStatus: 'pending',
        created_at: new Date()
    };
    const result = await orderCollections.insertOne(myOrders);
    res.send(result);
});

router.get("/dashboard/myOrders", async (req, res) => {
    const email = req.query.email;
    const myOrder = await orderCollections
        .find({ userEmail: email })
        .toArray();
    if (myOrder.length > 0) {
        res.send(myOrder);
    } else {
        res.send([]);
    }
});

router.get("/dashboard/pendingOrder", async (req, res) => {
    const result = await orderCollections.find().toArray();
    res.send(result);
});

module.exports = router;
