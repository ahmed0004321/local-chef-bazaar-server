const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { collections } = require('../config/db');
const { mealReviewCollections, mealCollections } = collections;

router.get("/reviews", async (req, res) => {
    try {
        const result = await mealReviewCollections
            .find()
            .sort({ created_at: -1 })
            .toArray();
        res.send(result);
    } catch (error) {
        res.status(500).send({ message: "Failed to fetch reviews" });
    }
});

router.post("/mealReviews/:id", async (req, res) => {
    const id = req.params.id;
    const review = req.body;
    const reviewDoc = {
        ...review,
        mealId: id,
        created_at: new Date(),
    };
    const result = await mealReviewCollections.insertOne(reviewDoc);
    res.send(result);
});

router.get("/mealReviews", async (req, res) => {
    const mealId = req.query.mealId;
    if (!mealId) {
        return res
            .status(400)
            .send({ error: "mealId query parameter is required" });
    }
    const result = await mealReviewCollections
        .find({ mealId: mealId })
        .toArray();
    res.send(result);
});

router.get("/dashboard/myReview", async (req, res) => {
    const email = req.query.email;
    try {
        const myReview = await mealReviewCollections.aggregate([
            { $match: { userEmail: email } },
            {
                $addFields: {
                    mealObjectId: { $toObjectId: "$mealId" }
                }
            },
            {
                $lookup: {
                    from: "meals",
                    localField: "mealObjectId",
                    foreignField: "_id",
                    as: "mealDetails"
                }
            },
            { $unwind: "$mealDetails" },
            {
                $project: {
                    mealObjectId: 0,
                }
            }
        ]).toArray();

        res.send(myReview);
    } catch (error) {
        console.error("Aggregation error:", error);
        const fallback = await mealReviewCollections.find({ userEmail: email }).toArray();
        res.send(fallback);
    }
});

router.patch("/dashboard/review/:id", async (req, res) => {
    const reviewId = req.params.id;
    const { text } = req.body;
    const result = await mealReviewCollections.updateOne(
        { _id: new ObjectId(reviewId) },
        { $set: { text } }
    );
    res.send(result);
});

router.delete("/dashboard/review/:id", async (req, res) => {
    const reviewId = req.params.id;
    const result = await mealReviewCollections.deleteOne({
        _id: new ObjectId(reviewId),
    });
    res.send(result);
});

router.get("/dashboard/myReview/:id", async (req, res) => {
    const mealId = req.params.id;
    const mealIdExist = await mealCollections
        .find({ _id: new ObjectId(mealId) })
        .toArray();
    if (mealIdExist) {
        res.send(mealIdExist);
    } else {
        res.send({ massage: "this particular meal id do not exist" });
    }
});

module.exports = router;
