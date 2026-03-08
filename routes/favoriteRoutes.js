const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { collections } = require('../config/db');
const { favMealCollections, mealCollections } = collections;

router.post("/favMeal/:id", async (req, res) => {
    const mealId = req.params.id;
    const { email } = req.body;

    if (!email) {
        return res.status(400).send({ message: "Email required" });
    }

    const mealExist = await mealCollections.findOne({
        _id: new ObjectId(mealId),
    });

    if (!mealExist) {
        return res.status(404).send({ message: "Meal not found" });
    }

    const alreadyFav = await favMealCollections.findOne({
        mealId: new ObjectId(mealId),
        email: email,
    });

    if (alreadyFav) {
        return res.status(409).send({ message: "Meal already favorited" });
    }

    const favDoc = {
        mealId: new ObjectId(mealId),
        email,
        created_at: new Date(),
    };

    const result = await favMealCollections.insertOne(favDoc);

    res.send({ message: "Favorite added successfully", result });
});

router.get("/favMeal", async (req, res) => {
    const email = req.query.email;
    if (!email) {
        return res.status(400).send({ message: "Email required" });
    }

    try {
        const result = await favMealCollections.aggregate([
            { $match: { email: email } },
            {
                $addFields: {
                    mealObjectId: {
                        $cond: {
                            if: { $eq: [{ $type: "$mealId" }, "objectId"] },
                            then: "$mealId",
                            else: { $toObjectId: "$mealId" }
                        }
                    }
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

        res.send(result);
    } catch (error) {
        console.error("Aggregation error in favMeal:", error);
        const fallback = await favMealCollections.find({ email: email }).toArray();
        res.send(fallback);
    }
});

router.delete("/favMeal/:id", async (req, res) => {
    const favId = req.params.id;
    const result = await favMealCollections.deleteOne({
        _id: new ObjectId(favId),
    });
    res.send(result);
});

module.exports = router;
