const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const { verifyFBToken } = require('../middlewares/auth');
const { collections } = require('../config/db');
const { blogCollections, userCollections } = collections;

router.post("/blogs", async (req, res) => {
    try {
        const blog = req.body;
        const blogDoc = {
            ...blog,
            createdAt: new Date(),
        };
        const result = await blogCollections.insertOne(blogDoc);
        res.send(result);
    } catch (error) {
        console.error("Error creating blog:", error);
        res.status(500).send({ message: "Failed to create blog" });
    }
});

router.get("/blogs/:id", async (req, res) => {
    try {
        const id = req.params.id;
        const result = await blogCollections.findOne({ _id: new ObjectId(id) });
        if (!result) {
            return res.status(404).send({ message: "Blog not found" });
        }
        res.send(result);
    } catch (error) {
        console.error("Error fetching blog:", error);
        res.status(500).send({ message: "Failed to fetch blog" });
    }
});

router.get("/blogs", async (req, res) => {
    try {
        const result = await blogCollections
            .find()
            .sort({ createdAt: -1 })
            .toArray();
        res.send(result);
    } catch (error) {
        console.error("Error fetching blogs:", error);
        res.status(500).send({ message: "Failed to fetch blogs" });
    }
});

router.delete("/blogs/:id", verifyFBToken, async (req, res) => {
    try {
        const id = req.params.id;
        const userEmail = req.decoded_email;

        const user = await userCollections.findOne({ email: userEmail });
        const isAdmin = user?.role === "admin";

        const blog = await blogCollections.findOne({ _id: new ObjectId(id) });
        if (!blog) {
            return res.status(404).send({ message: "Blog not found" });
        }

        if (blog.authorEmail !== userEmail && !isAdmin) {
            return res.status(403).send({ message: "You are not authorized to delete this blog" });
        }

        const result = await blogCollections.deleteOne({ _id: new ObjectId(id) });
        res.send(result);
    } catch (error) {
        console.error("Error deleting blog:", error);
        res.status(500).send({ message: "Failed to delete blog" });
    }
});

module.exports = router;
