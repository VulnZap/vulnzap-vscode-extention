// Subtle Vulnerabilities Test File
// These vulnerabilities are not immediately obvious but represent serious security flaws

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

// 1. BUSINESS LOGIC: Price Manipulation Vulnerability
// Attacker can set negative quantity to get money back
app.post('/purchase', async (req, res) => {
    const { productId, quantity, userId } = req.body;
    const product = await getProduct(productId);
    
    // VULNERABLE: No validation on quantity being positive
    const totalPrice = product.price * quantity; // Can be negative!
    
    await updateUserBalance(userId, -totalPrice); // User gets money for negative quantity
    await addToInventory(userId, productId, quantity);
    
    res.json({ success: true, charged: totalPrice });
});

// 2. BUSINESS LOGIC: Race Condition in Coupon Usage
// Multiple requests can use the same single-use coupon
app.post('/apply-coupon', async (req, res) => {
    const { couponCode, userId } = req.body;
    
    const coupon = await getCoupon(couponCode);
    if (!coupon || coupon.used) {
        return res.status(400).json({ error: 'Invalid coupon' });
    }
    
    // VULNERABLE: Race condition - coupon check and update not atomic
    // Multiple simultaneous requests can pass the check above
    await applyCouponDiscount(userId, coupon.discount);
    
    // This update happens after discount is applied - too late!
    await markCouponAsUsed(couponCode);
    
    res.json({ success: true, discount: coupon.discount });
});

// 3. AUTHORIZATION: Horizontal Privilege Escalation
// User can access other users' data by changing userId parameter
app.get('/user/:userId/orders', authenticateToken, async (req, res) => {
    const requestedUserId = req.params.userId;
    const authenticatedUserId = req.user.id;
    
    // VULNERABLE: No check if authenticated user can access requested user's data
    // Any authenticated user can view any other user's orders
    const orders = await getUserOrders(requestedUserId);
    
    res.json(orders);
});

// 4. BUSINESS LOGIC: Integer Overflow in Points System
// Large point values can overflow and wrap around
app.post('/redeem-points', async (req, res) => {
    const { userId, pointsToRedeem } = req.body;
    const user = await getUser(userId);
    
    // VULNERABLE: No bounds checking on point values
    // Large numbers can cause integer overflow
    const newBalance = user.points - pointsToRedeem; // Can overflow to large positive number
    
    if (newBalance >= 0) { // Check passes due to overflow
        await updateUserPoints(userId, newBalance);
        await grantReward(userId, pointsToRedeem);
        res.json({ success: true, newBalance });
    } else {
        res.status(400).json({ error: 'Insufficient points' });
    }
});

// 5. TIME-BASED: TOCTOU (Time of Check Time of Use)
// File permissions can change between check and use
app.post('/read-user-file', async (req, res) => {
    const { userId, filename } = req.body;
    const filePath = `/uploads/${userId}/${filename}`;
    
    // VULNERABLE: TOCTOU - file permissions checked here
    const hasPermission = await checkFilePermission(userId, filePath);
    if (!hasPermission) {
        return res.status(403).json({ error: 'No permission' });
    }
    
    // But file could be replaced with symlink to sensitive file here
    // by another process between check and use
    const content = fs.readFileSync(filePath, 'utf8'); // File used here
    
    res.json({ content });
});

// 6. BUSINESS LOGIC: Discount Stacking Vulnerability
// Multiple discounts can be applied when only one should be allowed
app.post('/apply-discount', async (req, res) => {
    const { orderId, discountCode } = req.body;
    const order = await getOrder(orderId);
    
    // VULNERABLE: No check if discount already applied
    // Users can apply multiple discounts to same order
    const discount = await getDiscount(discountCode);
    const newTotal = order.total * (1 - discount.percentage);
    
    await updateOrderTotal(orderId, newTotal);
    await logDiscountUsage(orderId, discountCode); // Just logs, doesn't prevent reuse
    
    res.json({ success: true, newTotal });
});

// 7. LOGIC: Password Reset Token Reuse
// Reset tokens can be used multiple times
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    
    const resetRequest = await getPasswordResetRequest(token);
    if (!resetRequest || resetRequest.expires < Date.now()) {
        return res.status(400).json({ error: 'Invalid or expired token' });
    }
    
    // VULNERABLE: Token not invalidated after use
    // Same token can be used multiple times to change password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await updateUserPassword(resetRequest.userId, hashedPassword);
    
    // Missing: await invalidateResetToken(token);
    
    res.json({ success: true });
});

// 8. BUSINESS LOGIC: Referral Bonus Exploitation
// Users can refer themselves or create fake accounts for bonuses
app.post('/refer-user', async (req, res) => {
    const { referrerId, newUserEmail } = req.body;
    
    // VULNERABLE: No validation that referrer != new user
    // No check for email similarity or patterns
    const newUser = await createUser(newUserEmail);
    
    // Users can refer themselves with slight email variations
    // like user+1@email.com, user+2@email.com
    await grantReferralBonus(referrerId, 50); // $50 bonus per referral
    await grantSignupBonus(newUser.id, 25);   // $25 signup bonus
    
    res.json({ success: true, bonusGranted: 50 });
});

// 9. TIMING: Subtle Timing Attack on User Enumeration
// Response times reveal if user exists
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    const user = await getUserByEmail(email);
    
    if (!user) {
        // VULNERABLE: Fast response for non-existent users
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Slow bcrypt comparison only for existing users
    // Timing difference reveals if email exists in system
    const validPassword = await bcrypt.compare(password, user.hashedPassword);
    
    if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
    res.json({ token });
});

// 10. BUSINESS LOGIC: Subscription Downgrade Exploitation
// Users can downgrade and immediately upgrade to reset usage limits
app.post('/change-subscription', async (req, res) => {
    const { userId, newPlan } = req.body;
    const user = await getUser(userId);
    
    // VULNERABLE: Usage limits reset on any plan change
    // Users can downgrade to free, then upgrade to reset API limits
    await updateUserPlan(userId, newPlan);
    await resetUsageLimits(userId); // Always resets, even for downgrades
    
    const newLimits = getPlanLimits(newPlan);
    res.json({ success: true, newLimits });
});

// 11. SUBTLE: JWT Secret in Error Messages
// JWT secret accidentally exposed in error responses
app.get('/protected', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ data: 'protected data', userId: decoded.userId });
    } catch (error) {
        // VULNERABLE: Error might contain JWT secret in stack trace
        console.error('JWT verification failed:', error);
        res.status(401).json({ 
            error: 'Invalid token',
            debug: error.message, // Could leak secret in some JWT libraries
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// 12. BUSINESS LOGIC: Withdrawal Limit Bypass
// Daily withdrawal limits can be bypassed with timezone manipulation
app.post('/withdraw', async (req, res) => {
    const { userId, amount, timezone } = req.body;
    
    // VULNERABLE: Uses user-provided timezone for limit calculation
    const userDate = new Date().toLocaleDateString('en-US', { timeZone: timezone });
    const todayWithdrawals = await getWithdrawalsForDate(userId, userDate);
    const totalToday = todayWithdrawals.reduce((sum, w) => sum + w.amount, 0);
    
    if (totalToday + amount > 10000) { // $10k daily limit
        return res.status(400).json({ error: 'Daily limit exceeded' });
    }
    
    // User can manipulate timezone to reset "today" and bypass limits
    await processWithdrawal(userId, amount);
    res.json({ success: true });
});

module.exports = app;
