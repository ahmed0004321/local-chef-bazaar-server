const express = require("express");
const { MongoClient, ServerApiVersion } = require('mongodb');
const cors = require("cors");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

//middleware
app.use(cors());
app.use(express.json());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster007.lqqnzz4.mongodb.net/?appName=Cluster007`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    //database 
    const db = client.db('local_chef_bazar_db');
    const mealCollections = db.collection('meals');
    //here will all the apis has to be written

    //to show all meals
    app.get('/meals', async (req, res) => {
        const result = await mealCollections.find().toArray();
        res.send(result);
    })




















    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
  }
}
run().catch(console.dir);


app.get("/", (req, res) => {
    res.send("LocalChefBazaar Server is Running 🚀");
  });
  //listening the server
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });