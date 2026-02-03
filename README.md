# Local Chef Bazaar API 🚀 - Professional Backend Engine

The robust backend core for the Local Chef Bazaar marketplace, handling complex aggregations, secure transactions, and multi-role authentication.

**API Server**: [https://local-chef-bazaar-server-nine.vercel.app](https://local-chef-bazaar-server-nine.vercel.app)

## ⚙️ Core Functionality

### 🔐 Advanced Authentication
- **Firebase Admin SDK Integration**: Secure verification of ID tokens for role-protected endpoints.
- **Role-Based Access Control (RBAC)**: Middleware-driven security for Admin and Chef specific operations.

### 📈 Business Intelligence
- **Aggregation Pipelines**: High-performance MongoDB aggregations for:
  - Monthly Revenue trends using `$toDate` and `$dateToString`.
  - Top Selling Meals by volume and revenue.
  - Real-time Platform Profit calculation (20% commission logic).
  - User and Role distribution metrics.

### 💳 Transaction Management
- **Stripe Integration**: Secure payment processing with status tracking (Pending -> Paid).
- **Order Lifecycle**: End-to-end management from Pending -> Accepted -> Delivered.

## 🛠️ Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB (Atlas)
- **Auth/Security**: Firebase Admin SDK, JWT concepts.
- **Environment**: Dotenv for secure secret management.
- **Deployment Ready**: Optimized for Vercel/Render hosting.

## 🚀 Getting Started

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ahmed0004321/local-chef-bazaar-server.git
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Environment Setup**:
   Required variables in `.env`:
   - `DB_USER` / `DB_PASS`
   - `STRIPE_SECRET_KEY`
   - `FIREBASE_ADMIN_SDK_JSON`

4. **Run Server**:
   ```bash
   npm start
   ```

## 🛣️ API Endpoints Overview

- `GET /admin/stats`: Deep analytics for platform health.
- `GET /requests`: Unified stream for role applications.
- `PATCH /users/fraud/:id`: Moderation tools for platform integrity.
- `POST /favMeal`: Normalized meal bookmarking with ObjectId support.

---
Robustly engineered by [Oasif Ahmed](https://github.com/ahmed0004321)
