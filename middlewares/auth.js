const admin = require("../config/firebase");

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

module.exports = { verifyFBToken };
