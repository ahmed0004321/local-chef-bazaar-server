const express = require('express');
const router = express.Router();
const { verifyFBToken } = require('../middlewares/auth');
const { collections } = require('../config/db');
const { userCollections, orderCollections, mealCollections, mealReviewCollections, favMealCollections } = collections;

// Admin Stats
router.get("/admin/stats", verifyFBToken, async (req, res) => {
    try {
        const totalUsers = await userCollections.countDocuments();
        const totalOrders = await orderCollections.countDocuments();
        const pendingOrders = await orderCollections.countDocuments({ orderStatus: "pending" });
        const deliveredOrders = await orderCollections.countDocuments({ orderStatus: { $in: ["delivered", "accepted"] } });
        const totalChefs = await userCollections.countDocuments({ role: "chef" });

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

        const roleDistribution = await userCollections.aggregate([
            { $group: { _id: "$role", count: { $sum: 1 } } }
        ]).toArray();

        const revenueData = await orderCollections.aggregate([
            { $match: { paymentStatus: "paid" } },
            { $group: { _id: null, totalRevenue: { $sum: { $toDouble: "$price" } } } }
        ]).toArray();
        const totalRevenue = revenueData.length > 0 ? revenueData[0].totalRevenue : 0;
        const totalProfit = totalRevenue * 0.2;

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

// Chef Stats
router.get("/chef/stats/:email", verifyFBToken, async (req, res) => {
    try {
        const email = req.params.email;
        if (req.decoded_email !== email) {
            return res.status(403).send({ message: "Forbidden access" });
        }

        const totalMeals = await mealCollections.countDocuments({ userEmail: email });
        const orders = await orderCollections.find({ chefEmail: email }).toArray();

        const revenueData = await orderCollections.aggregate([
            { $match: { chefEmail: email, paymentStatus: "paid" } },
            { $group: { _id: null, total: { $sum: { $toDouble: "$price" } } } }
        ]).toArray();
        const totalRevenue = revenueData.length > 0 ? revenueData[0].total : 0;

        const totalOrders = await orderCollections.countDocuments({ chefEmail: email });
        const pendingOrders = await orderCollections.countDocuments({ chefEmail: email, orderStatus: "pending" });

        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        const dailySales = await orderCollections.aggregate([
            {
                $match: {
                    chefEmail: email,
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

        res.send({
            totalMeals,
            totalRevenue,
            totalOrders,
            pendingOrders,
            dailySales
        });
    } catch (error) {
        console.error("Chef Stats Error:", error);
        res.status(500).send({ message: "Error fetching chef stats" });
    }
});

// Customer Stats
router.get("/customer/stats/:email", verifyFBToken, async (req, res) => {
    try {
        const email = req.params.email;
        if (req.decoded_email !== email) {
            return res.status(403).send({ message: "Forbidden access" });
        }

        const totalOrders = await orderCollections.countDocuments({ userEmail: email });
        const totalReviews = await mealReviewCollections.countDocuments({ userEmail: email });
        const totalFavorites = await favMealCollections.countDocuments({ email: email });

        const totalSpentData = await orderCollections.aggregate([
            { $match: { userEmail: email, paymentStatus: "paid" } },
            { $group: { _id: null, total: { $sum: { $toDouble: "$price" } } } }
        ]).toArray();
        const totalSpent = totalSpentData.length > 0 ? totalSpentData[0].total : 0;

        const recentOrders = await orderCollections.find({ userEmail: email })
            .sort({ created_at: -1 })
            .limit(5)
            .toArray();

        res.send({
            totalOrders,
            totalReviews,
            totalFavorites,
            totalSpent,
            recentOrders
        });
    } catch (error) {
        console.error("Customer Stats Error:", error);
        res.status(500).send({ message: "Error fetching customer stats" });
    }
});

module.exports = router;
