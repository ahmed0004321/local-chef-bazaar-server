const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;


const admin = require("firebase-admin");

const serviceAccount = require("./local-chef-bazaar-client-firebase-adminsdk-fbsvc-cf7e3a980e.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});


//middleware
app.use(cors());
app.use(express.json());

const verifyFBToken = async (req, res, next) => {
  // console.log('header in the middleware', req.headers.authorization);
  const token = req.headers.authorization;
  if(!token){
    return res.status(401).send({massage: 'unauthorized access!!'})
  }
  try{
    const tokenId = token.split(' ')[1]
    const decoded = await admin.auth().verifyIdToken(tokenId);
    console.log('decoded in the token', decoded);
    const decoded_email = decoded.email;
    next();
  }catch(err){
    return res.status(401).send({massage: 'unauthorized access'})
  }
}



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster007.lqqnzz4.mongodb.net/?appName=Cluster007`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    //database
    const db = client.db("local_chef_bazar_db");
    const userCollections = db.collection("users");
    const mealCollections = db.collection("meals");
    const orderCollections = db.collection("myOrders");
    const mealReviewCollections = db.collection("mealReviews");
    //here will all the apis has to be written

    //order related apis
    app.post('/myOrders', async (req, res) => {
      const orders = req.body;
      const myOrders = {...orders, created_at: new Date()};
      const result = await orderCollections.insertOne(myOrders);
      res.send(result);
    })



    //user related apis
    app.post('/users', async (req, res) => {
      const user = req.body;
      user.role = 'customer';
      created_at: new Date();
      const email = user.email;
      const userExists = await userCollections.findOne({email});
      if(userExists){
        return res.send({massage: 'user already exist'})
      }
      const result = await userCollections.insertOne(user);
      res.send(result);
    })


    //to show all meals
    app.get("/meals", verifyFBToken, async (req, res) => {
      const result = await mealCollections.find().toArray();
      res.send(result);
    });
    //to show only 6 meals in homepage
    app.get("/mealForHome", async (req, res) => {
      const result = await mealCollections.find().limit(6).toArray();
      res.send(result);
    });
    //to show specific meal details
    app.get("/mealDetails/:id", async (req, res) => {
      const id = req.params.id;
      const result = await mealCollections.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });
    //meal review api
    app.post("/mealReviews/:id", async (req, res) => {
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
    //get all teh review
    app.get("/mealReviews", async (req, res) => {
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

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
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
