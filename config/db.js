const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config();

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster007.lqqnzz4.mongodb.net/?appName=Cluster007`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

const db = client.db("local_chef_bazar_db");

const collections = {
    userCollections: db.collection("users"),
    mealCollections: db.collection("meals"),
    orderCollections: db.collection("myOrders"),
    mealReviewCollections: db.collection("mealReviews"),
    favMealCollections: db.collection("favMeal"),
    requestCollections: db.collection("requests"),
    blogCollections: db.collection("blogs"),
    subscriberCollections: db.collection("subscribers"),
    complaintCollections: db.collection("complaints"),
};

async function connectDB() {
    try {
        await client.connect();
        await client.db("admin").command({ ping: 1 });
        console.log("✅ Successfully connected to MongoDB!");
    } catch (error) {
        console.error("❌ MongoDB connection failed:", error);
        process.exit(1);
    }
}

module.exports = {
    client,
    db,
    collections,
    connectDB
};
