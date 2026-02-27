const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const cors = require("cors");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_KEY);

const app = express();
const port = process.env.PORT || 3000;

const admin = require("firebase-admin");

const serviceAccountVar = process.env.FIREBASE_SERVICE_ACCOUNT;
let serviceAccount;

if (!serviceAccountVar) {
  // Fallback to local file if env var not present (backward compatibility)
  try {
    serviceAccount = require("./local-chef-bazaar-client-firebase-adminsdk-fbsvc-cf7e3a980e.json");
    console.log("Initializing Firebase using local file");
  } catch (e) {
    console.error("FIREBASE_SERVICE_ACCOUNT not defined and local file not found.");
  }
} else if (serviceAccountVar.startsWith("{")) {
  try {
    console.log("Initializing Firebase using JSON string from environment variable");
    serviceAccount = JSON.parse(serviceAccountVar);
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, "\n");
  } catch (e) {
    console.error("Failed to parse FIREBASE_SERVICE_ACCOUNT as JSON:", e.message);
  }
} else {
  console.log("Initializing Firebase using file path:", serviceAccountVar);
  serviceAccount = require(serviceAccountVar);
}

if (serviceAccount) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} else {
  console.warn("Firebase admin not initialized due to missing credentials.");
}

//middleware
const corsOptions = {
  origin: [
    "http://localhost:5173",
    "https://local-chef-bazaar-client.vercel.app"
  ],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;
  if (!token || !token.startsWith("Bearer ")) {
    return res.status(401).send({ message: "unauthorized access!!" });
  }
  try {
    const tokenId = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(tokenId);
    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "unauthorized access" });
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

// Database Collections
const db = client.db("local_chef_bazar_db");
const userCollections = db.collection("users");
const mealCollections = db.collection("meals");
const orderCollections = db.collection("myOrders");
const mealReviewCollections = db.collection("mealReviews");
const favMealCollections = db.collection("favMeal");
const requestCollections = db.collection("requests");
const blogCollections = db.collection("blogs");

// Middleware to ensure DB connection
// Connect to MongoDB once at startup
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

// Initialize DB connection
connectDB();


//payment integration related api
app.get("/dashboard/orderPayment/:id", async (req, res) => {
  const orderId = req.params.id;
  if (!orderId) {
    res.send({ massage: "id not found" });
  }
  const result = await orderCollections.findOne({
    _id: new ObjectId(orderId),
  });
  res.send(result);
});

app.post("/create-checkout-session", async (req, res) => {
  const paymentInfo = req.body;
  const amount = parseFloat(paymentInfo.price) * 100;

  const siteDomain = process.env.SITE_DOMAIN || "https://local-chef-bazaar-client.vercel.app";

  // Standardized redirect URLs matching frontend Routes.jsx
  const successUrl = `${siteDomain}/payment-success?session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = `${siteDomain}/payment-cancel`;

  console.log("Stripe Redirects -> Success:", successUrl);
  console.log("Stripe Redirects -> Cancel:", cancelUrl);

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

app.patch("/payment-success", async (req, res) => {
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

// Get only successful payments
app.get("/dashboard/payments", async (req, res) => {
  const result = await orderCollections
    .find({ paymentStatus: "paid" })
    .sort({ created_at: -1 })
    .toArray();
  res.send(result);
});

// Get all reviews in home page
app.get("/reviews", async (req, res) => {
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

// Admin Stats - Professional Version
app.get("/admin/stats", verifyFBToken, async (req, res) => {
  try {
    const totalUsers = await userCollections.countDocuments();
    const totalOrders = await orderCollections.countDocuments();
    const pendingOrders = await orderCollections.countDocuments({ orderStatus: "pending" });
    const deliveredOrders = await orderCollections.countDocuments({ orderStatus: { $in: ["delivered", "accepted"] } });
    const totalChefs = await userCollections.countDocuments({ role: "chef" });

    // Today's Sales
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const todayRevenueData = await orderCollections.aggregate([
      {
        $match: {
          paymentStatus: "paid",
          created_at: { $gte: todayStart }
        }
      },
      { $group: { _id: null, total: { $sum: { $toDouble: "$price" } } } }
    ]).toArray();
    const todayRevenue = todayRevenueData.length > 0 ? todayRevenueData[0].total : 0;

    // Role Distribution
    const roleDistribution = await userCollections.aggregate([
      { $group: { _id: "$role", count: { $sum: 1 } } }
    ]).toArray();

    // Total Revenue
    const revenueData = await orderCollections.aggregate([
      { $match: { paymentStatus: "paid" } },
      { $group: { _id: null, totalRevenue: { $sum: { $toDouble: "$price" } } } }
    ]).toArray();
    const totalRevenue = revenueData.length > 0 ? revenueData[0].totalRevenue : 0;
    const totalProfit = totalRevenue * 0.2; // 20% Platform Commission

    // Daily Sales Trends (Last 7 Days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const dailySales = await orderCollections.aggregate([
      {
        $match: {
          paymentStatus: "paid",
          created_at: { $gte: sevenDaysAgo }
        }
      },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: { $toDate: "$created_at" } } },
          revenue: { $sum: { $toDouble: "$price" } }
        }
      },
      { $sort: { "_id": 1 } },
      { $project: { date: "$_id", revenue: 1, _id: 0 } }
    ]).toArray();

    // Recent Orders (with customer names)
    const recentOrders = await orderCollections.aggregate([
      { $sort: { created_at: -1 } },
      { $limit: 5 },
      {
        $lookup: {
          from: "users",
          localField: "userEmail",
          foreignField: "email",
          as: "userDetails"
        }
      },
      {
        $project: {
          orderId: "$_id",
          customer: { $ifNull: [{ $arrayElemAt: ["$userDetails.displayName", 0] }, "$userEmail"] },
          amount: "$price",
          status: "$orderStatus",
          date: "$created_at",
          _id: 0
        }
      }
    ]).toArray();

    // Top Selling Meals (with images)
    const topMeals = await orderCollections.aggregate([
      { $group: { _id: "$mealName", sales: { $sum: 1 }, revenue: { $sum: { $toDouble: "$price" } } } },
      { $sort: { sales: -1 } },
      { $limit: 5 },
      {
        $lookup: {
          from: "meals",
          localField: "_id",
          foreignField: "foodName",
          as: "mealDetails"
        }
      },
      {
        $project: {
          name: "$_id",
          sales: 1,
          image: { $arrayElemAt: ["$mealDetails.foodImage", 0] },
          _id: 0
        }
      }
    ]).toArray();

    res.send({
      stats: {
        totalUsers,
        totalOrders,
        pendingOrders,
        deliveredOrders,
        totalRevenue,
        totalProfit,
        todayRevenue,
        totalChefs
      },
      roleDistribution,
      dailySales,
      recentOrders,
      topMeals
    });
  } catch (error) {
    console.error("Stats Error:", error);
    res.status(500).send({ message: "Error fetching stats" });
  }
});

//here will all the apis has to be written

//chef apis
//getting customer order request for specific chef
app.get('/dashboard/orderRequest/:id', async (req, res) => {
  const chefId = req.params.id;
  if (!chefId) {
    res.send({ massage: 'id not found' });
  }
  const result = await orderCollections.find({ chefId }).toArray();
  res.send(result);
});
//updating order status & payment status
app.patch("/dashboard/orderUpdate/:id", async (req, res) => {
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

//inserting created meals to the mealscollections
app.post("/dashboard/createMeals", async (req, res) => {
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
      userEmail: createdMeals.userEmail // Check if THIS chef already has a meal with this name
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

//show my meals using specific chef email 
app.get('/dashboard/myMeals', async (req, res) => {
  const chefEmail = req.query.email;
  if (!chefEmail) {
    res.send({ massage: 'email not found' });
  }
  const result = await mealCollections.find({ userEmail: chefEmail }).toArray();
  res.send(result);
});

//update myMeals 
app.patch('/dashboard/myMeals/:id', async (req, res) => {
  const mealId = req.params.id;
  const updatedMeal = req.body;
  if (!mealId) {
    res.send('meal Id not found');
  }
  const result = await mealCollections.updateOne({ _id: new ObjectId(mealId) },
    { $set: updatedMeal });
  res.send(result);
});
//delete myMeals
app.delete('/dashboard/myMeals/:id', async (req, res) => {
  const mealId = req.params.id;
  const result = await mealCollections.deleteOne({ _id: new ObjectId(mealId) });
  res.send(result);
});

//show my review
app.get("/dashboard/myReview", async (req, res) => {
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
    // Fallback to simple find if aggregation fails (e.g. invalid mealId string)
    const fallback = await mealReviewCollections.find({ userEmail: email }).toArray();
    res.send(fallback);
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
    mealId: new ObjectId(mealId),
    email,
    created_at: new Date(),
  };

  const result = await favMealCollections.insertOne(favDoc);

  res.send({ message: "Favorite added successfully", result });
});

//get all fav meal
app.get("/favMeal", async (req, res) => {
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
    // Fallback to simple find if aggregation fails
    const fallback = await favMealCollections.find({ email: email }).toArray();
    res.send(fallback);
  }
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

  const userExists = await userCollections.findOne({ email });
  if (userExists) {
    // Update profile info if it's provided and different/missing
    const updateDoc = {};
    if (user.displayName && user.displayName !== userExists.displayName) {
      updateDoc.displayName = user.displayName;
    }
    if (user.photoURL && user.photoURL !== userExists.photoURL) {
      updateDoc.photoURL = user.photoURL;
    }

    if (Object.keys(updateDoc).length > 0) {
      await userCollections.updateOne({ email }, { $set: updateDoc });
      const updatedUser = await userCollections.findOne({ email });
      return res.send(updatedUser);
    }
    return res.send(userExists);
  }

  const newUser = {
    ...user,
    role: "customer",
    status: "active",
    created_at: new Date(),
  };
  await userCollections.insertOne(newUser);
  res.send(newUser);
});

//get all users for admin with stats
app.get("/users/admin", verifyFBToken, async (req, res) => {
  try {
    const result = await userCollections.aggregate([
      {
        $lookup: {
          from: "myOrders",
          localField: "email",
          foreignField: "userEmail",
          as: "orders"
        }
      },
      {
        $addFields: {
          ordersCount: { $size: "$orders" },
          totalSpent: {
            $reduce: {
              input: "$orders",
              initialValue: 0,
              in: {
                $add: [
                  "$$value",
                  {
                    $cond: [
                      { $eq: ["$$this.paymentStatus", "paid"] },
                      { $toDouble: { $ifNull: ["$$this.price", 0] } },
                      0
                    ]
                  }
                ]
              }
            }
          },
          lastOrder: { $arrayElemAt: ["$orders.created_at", -1] }
        }
      },
      {
        $project: {
          orders: 0
        }
      }
    ]).toArray();
    res.send(result);
  } catch (error) {
    console.error("Error fetching users for admin:", error);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

//make user fraud
app.patch("/users/fraud/:id", verifyFBToken, async (req, res) => {
  const id = req.params.id;
  const filter = { _id: new ObjectId(id) };
  const updateDoc = {
    $set: {
      status: "fraud",
    },
  };
  const result = await userCollections.updateOne(filter, updateDoc);
  res.send(result);
});

// Bulk actions
app.patch("/users/bulk-fraud", verifyFBToken, async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids)) {
    return res.status(400).send({ message: "Invalid IDs" });
  }
  const filter = { _id: { $in: ids.map(id => new ObjectId(id)) } };
  const updateDoc = { $set: { status: "fraud" } };
  const result = await userCollections.updateMany(filter, updateDoc);
  res.send(result);
});

app.delete("/users/bulk-delete", verifyFBToken, async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids)) {
    return res.status(400).send({ message: "Invalid IDs" });
  }
  const filter = { _id: { $in: ids.map(id => new ObjectId(id)) } };
  const result = await userCollections.deleteMany(filter);
  res.send(result);
});

// Update specific user
app.patch("/users/:id", verifyFBToken, async (req, res) => {
  const id = req.params.id;
  const updateData = req.body;
  const filter = { _id: new ObjectId(id) };

  // Prevent sensitive field updates if necessary, but for admin it's generally okay
  delete updateData._id;

  const updateDoc = { $set: updateData };
  const result = await userCollections.updateOne(filter, updateDoc);
  res.send(result);
});


// Consolidated Admin Request Management system
app.post("/requests", async (req, res) => {
  const request = req.body;

  const existingRequest = await requestCollections.findOne({
    userEmail: request.userEmail,
    requestType: request.requestType,
    requestStatus: "pending"
  });

  if (existingRequest) {
    return res.status(409).send({ message: "A pending request of this type already exists." });
  }

  const newRequest = {
    ...request,
    requestStatus: "pending",
    requestTime: new Date(),
  };
  const result = await requestCollections.insertOne(newRequest);
  res.send(result);
});

app.get("/requests", verifyFBToken, async (req, res) => {
  const result = await requestCollections.find().toArray();
  res.send(result);
});

app.patch("/requests/:id", verifyFBToken, async (req, res) => {
  const id = req.params.id;
  const { status, userEmail, requestType } = req.body;

  try {
    const filter = { _id: new ObjectId(id) };
    const updateDoc = {
      $set: { requestStatus: status },
    };

    const result = await requestCollections.updateOne(filter, updateDoc);

    if (status === "approved" && result.modifiedCount > 0) {
      const userFilter = { email: userEmail };
      let userUpdateDoc = { $set: { role: requestType } };

      if (requestType === "chef") {
        const randomNum = Math.floor(1000 + Math.random() * 9000);
        const chefId = `chef-${randomNum}`;
        userUpdateDoc.$set.chefId = chefId;
      }

      await userCollections.updateOne(userFilter, userUpdateDoc);
    }

    res.send(result);
  } catch (error) {
    console.error("Error updating request:", error);
    res.status(500).send({ message: "Failed to update request" });
  }
});

//user role update to make fraud
app.patch("/dashboard/manageUserRoleFraud/:id", async (req, res) => {
  const userId = req.params.id;
  const result = await userCollections.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { status: "fraud" } },
  );
  res.send(result);
});

//getting panding orders
app.get("/dashboard/pendingOrder", async (req, res) => {
  const result = await orderCollections.find().toArray();
  res.send(result);
});

//count user
app.get("/dashboard/countUser", async (req, res) => {
  const result = await userCollections.find().toArray();
  res.send(result);
});

//to show all meals (with pagination)
app.get("/meals", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const totalMeals = await mealCollections.countDocuments();
    const meals = await mealCollections
      .find()
      .skip(skip)
      .limit(limit)
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


app.get("/", (req, res) => {
  res.send("LocalChefBazaar Server is Running 🚀");
});

//listening the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

// Blog Related APIs
app.post("/blogs", async (req, res) => {
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

app.get("/blogs/:id", async (req, res) => {
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

app.get("/blogs", async (req, res) => {
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

app.delete("/blogs/:id", verifyFBToken, async (req, res) => {
  try {
    const id = req.params.id;
    const userEmail = req.decoded_email;

    // Check if user is Admin
    const user = await userCollections.findOne({ email: userEmail });
    const isAdmin = user?.role === "admin";

    // Ownership/Admin check
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

module.exports = app;
