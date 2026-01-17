const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

const admin = require("firebase-admin");

const serviceAccount = require("./local-chef-bazaar-client-firebase-adminsdk-fbsvc-cf7e3a980e.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

//middleware
app.use(cors());
app.use(express.json());

const verifyFBToken = async (req, res, next) => {
  // console.log('header in the middleware', req.headers.authorization);
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).send({ massage: "unauthorized access!!" });
  }
  try {
    const tokenId = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(tokenId);
    console.log("decoded in the token", decoded);
    const decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ massage: "unauthorized access" });
  }
};

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
    const favMealCollections = db.collection("favMeal");
    //here will all the apis has to be written

    //chef apis
    //inserting created meals to the mealscollections
    app.post("/dashboard/createMeals", async (req, res) => {
      try {
        const createdMeals = req.body;
        if (
          !createdMeals.foodName ||
          !createdMeals.chefName ||
          !createdMeals.price
        ) {
          return res
            .status(400)
            .send({ message: "Food Name, Chef Name, and Price are required" });
        }
        
        const existingMeal = await mealCollections.findOne({
          foodName: createdMeals.foodName,
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

    //show my review
    app.get("/dashboard/myReview", async (req, res) => {
      const email = req.query.email;
      const myReview = await mealReviewCollections
        .find({ userEmail: email })
        .toArray();
      if (myReview.length > 0) {
        res.send(myReview);
      } else {
        res.send([]);
      }
    });
    //update review
    app.patch("/dashboard/review/:id", async (req, res) => {
      reviewId = req.params.id;
      const { text } = req.body;
      const result = await mealReviewCollections.updateOne(
        { _id: new ObjectId(reviewId) },
        { $set: { text } }
      );
      res.send(result);
    });
    //delete
    app.delete("/dashboard/review/:id", async (req, res) => {
      const reviewId = req.params.id;
      const result = await mealReviewCollections.deleteOne({
        _id: new ObjectId(reviewId),
      });
      res.send(result);
    });
    //getting meal name by fetching mealcollection using id
    app.get("/dashboard/myReview/:id", async (req, res) => {
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

    //fav meal
    app.post("/favMeal/:id", async (req, res) => {
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
        ...mealExist,
        email,
        created_at: new Date(),
      };

      const result = await favMealCollections.insertOne(favDoc);

      res.send({ message: "Favorite added successfully", result });
    });

    //get all fav meal
    app.get("/favMeal", async (req, res) => {
      const emails = req.query.email;
      if (!emails) {
        res.send({ massage: "no fav meal found in this user" });
      }
      const result = await favMealCollections.find({ email: emails }).toArray();
      res.send(result);
    });
    //delete fav meal
    app.delete("/favMeal/:id", async (req, res) => {
      const favId = req.params.id;
      const result = await favMealCollections.deleteOne({
        _id: new ObjectId(favId),
      });
      res.send(result);
    });

    //order related apis
    app.post("/myOrders", async (req, res) => {
      const orders = req.body;
      const myOrders = { ...orders, created_at: new Date() };
      const result = await orderCollections.insertOne(myOrders);
      res.send(result);
    });
    //showing order to dashboard
    app.get("/dashboard/myOrders", async (req, res) => {
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

    //user related apis

    app.get("/myProfile", async (req, res) => {
      const email = req.query.email;
      if (!email) {
        return res.status(400).json({ error: "Email is required" });
      }

      try {
        const user = await userCollections.findOne({ email: email });

        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        res.json(user);
      } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });

    app.post("/users", async (req, res) => {
      const user = req.body;
      const email = user?.email;
      // console.log(user);
      const userExists = await userCollections.findOne({ email });
      if (userExists) {
        return res.send(userExists);
      }
      const newUser = {
        ...user,
        role: "customer",
        status: "active",
        created_at: new Date(),
      };
      const result = await userCollections.insertOne(newUser);
      res.send(newUser);
    });

    //to show all meals
    app.get("/meals", async (req, res) => {
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
