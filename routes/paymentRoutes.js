const express = require('express');
const router = express.Router();
const stripe = require("stripe")(process.env.STRIPE_KEY);
const { ObjectId } = require('mongodb');
const { collections } = require('../config/db');
const { orderCollections } = collections;

router.get("/dashboard/orderPayment/:id", async (req, res) => {
    const orderId = req.params.id;
    if (!orderId) {
        return res.send({ massage: "id not found" });
    }
    const result = await orderCollections.findOne({
        _id: new ObjectId(orderId),
    });
    res.send(result);
});

router.post("/create-checkout-session", async (req, res) => {
    const paymentInfo = req.body;
    const amount = parseFloat(paymentInfo.price) * 100;

    const siteDomain = process.env.SITE_DOMAIN || "https://local-chef-bazaar-client.vercel.app";

    const successUrl = `${siteDomain}/payment-success?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = `${siteDomain}/payment-cancel`;

    try {
        const session = await stripe.checkout.sessions.create({
            line_items: [
                {
                    price_data: {
                        currency: "USD",
                        unit_amount: amount,
                        product_data: {
                            name: paymentInfo.mealName,
                        },
                    },
                    quantity: 1,
                },
            ],
            customer_email: paymentInfo.userEmail,
            mode: "payment",
            metadata: {
                orderId: paymentInfo.orderId,
            },
            success_url: successUrl,
            cancel_url: cancelUrl,
        });
        res.send({ url: session.url });
    } catch (error) {
        console.error("Stripe Session Error:", error);
        res.status(500).send({ error: error.message });
    }
});

router.patch("/payment-success", async (req, res) => {
    const sessionId = req.query.session_id;
    if (!sessionId) return res.status(400).send({ message: "session_id is required" });

    try {
        const session = await stripe.checkout.sessions.retrieve(sessionId);
        if (session.payment_status === "paid") {
            const id = session.metadata.orderId;
            const query = { _id: new ObjectId(id) };
            const update = { $set: { paymentStatus: "paid" } };
            const result = await orderCollections.updateOne(query, update);

            return res.send({ success: true, result });
        }
        res.send({ success: false, status: session.payment_status });
    } catch (err) {
        console.error("Payment Sync Err:", err);
        res.status(500).send({ message: "Failed to verify payment" });
    }
});

router.get("/dashboard/payments", async (req, res) => {
    const result = await orderCollections
        .find({ paymentStatus: "paid" })
        .sort({ created_at: -1 })
        .toArray();
    res.send(result);
});

module.exports = router;
