const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { collections } = require('../config/db');
const { mealCollections, userCollections } = collections;

router.post("/dashboard/createMeals", async (req, res) => {
    try {
        const createdMeals = req.body;
        if (
            !createdMeals.foodName ||
            !createdMeals.chefName ||
            !createdMeals.price ||
            !createdMeals.userEmail
        ) {
            return res
                .status(400)
                .send({ message: "Food Name, Chef Name, Price and User Email are required" });
        }

        const user = await userCollections.findOne({ email: createdMeals.userEmail });
        if (user?.status === "fraud") {
            return res.status(403).send({ message: "Fraud users cannot create meals" });
        }

        const existingMeal = await mealCollections.findOne({
            foodName: createdMeals.foodName,
            userEmail: createdMeals.userEmail
        });

        if (existingMeal) {
            return res
                .status(409)
                .send({ message: "Meal with this name already exists" });
        }

        const meal = {
            ...createdMeals,
            createdAt: new Date(),
        };

        const result = await mealCollections.insertOne(meal);

        res.send({
            message: "Meal added successfully",
            insertedId: result.insertedId,
        });
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Internal Server Error" });
    }
});

router.get('/dashboard/myMeals', async (req, res) => {
    const chefEmail = req.query.email;
    if (!chefEmail) {
        res.send({ massage: 'email not found' });
    }
    const result = await mealCollections.find({ userEmail: chefEmail }).toArray();
    res.send(result);
});

router.patch('/dashboard/myMeals/:id', async (req, res) => {
    const mealId = req.params.id;
    const updatedMeal = req.body;
    if (!mealId) {
        res.send('meal Id not found');
    }
    const result = await mealCollections.updateOne({ _id: new ObjectId(mealId) },
        { $set: updatedMeal });
    res.send(result);
});

router.delete('/dashboard/myMeals/:id', async (req, res) => {
    const mealId = req.params.id;
    const result = await mealCollections.deleteOne({ _id: new ObjectId(mealId) });
    res.send(result);
});

router.get("/meals", async (req, res) => {
    try {
        const { page = 1, limit = 10, category, searchTerm, sort, deliveryArea } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const query = {};
        if (category) {
            query.category = { $regex: category, $options: "i" };
        }
        if (deliveryArea) {
            query.deliveryArea = { $regex: deliveryArea, $options: "i" };
        }
        if (searchTerm) {
            query.$or = [
                { foodName: { $regex: searchTerm, $options: "i" } },
                { chefName: { $regex: searchTerm, $options: "i" } },
            ];
        }

        let sortOptions = { createdAt: -1 };
        if (sort === "asc") {
            sortOptions = { price: 1 };
        } else if (sort === "desc") {
            sortOptions = { price: -1 };
        }

        const totalMeals = await mealCollections.countDocuments(query);
        const meals = await mealCollections
            .find(query)
            .sort(sortOptions)
            .skip(skip)
            .limit(parseInt(limit))
            .toArray();

        res.send({
            meals,
            totalMeals,
        });
    } catch (err) {
        console.error(err);
        res.status(500).send({ message: "Server Error" });
    }
});

router.get("/mealForHome", async (req, res) => {
    const result = await mealCollections.find().limit(6).toArray();
    res.send(result);
});

router.get("/mealDetails/:id", async (req, res) => {
    const id = req.params.id;
    const result = await mealCollections.findOne({ _id: new ObjectId(id) });
    res.send(result);
});

module.exports = router;
