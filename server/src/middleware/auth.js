import jwt from 'jsonwebtoken';
import { User } from '../models/User.js';

export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const [, token] = authHeader.split(' '); // "Bearer <token>"
  if (!token) return res.status(401).json({ message: 'Missing token' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // payload contains: id, name, role
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// Role-based access control - checks role from JWT token (no DB query)
export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Authentication required' });
    }
    
    if (!req.user.role || !roles.includes(req.user.role)) {
      return res.status(403).json({ 
        message: 'Access denied. Insufficient permissions.',
        requiredRole: roles,
        userRole: req.user.role || 'none'
      });
    }
    
    return next();
  };
}

// Convenience middleware - requires admin role
export const requireAdmin = requireRole('admin');

// Convenience middleware - requires student or admin role
export const requireStudent = requireRole('student', 'admin');
