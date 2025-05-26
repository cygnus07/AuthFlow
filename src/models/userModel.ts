import  { Schema, model } from 'mongoose';
import { UserDocument, UserRole, AccountStatus } from '../types/userTypes';

// Address schema (optional - can be removed if not needed)
const addressSchema = new Schema({
  fullName: { type: String },
  addressLine1: { type: String },
  addressLine2: { type: String },
  city: { type: String },
  state: { type: String },
  postalCode: { type: String },
  country: { type: String },
  phone: { type: String },
  isDefault: { type: Boolean, default: false }
}, { _id: true, timestamps: false });

// User schema
const userSchema = new Schema<UserDocument>({
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    trim: true 
  },
  password: { 
    type: String, 
    required: function() {
      // Password is required unless auth is via OAuth
      return !(this.googleId || this.facebookId || this.githubId);
    } 
  },
  username: {
    type: String,
    unique: true,
    sparse: true,
    trim: true
  },
  firstName: { 
    type: String, 
    trim: true 
  },
  lastName: { 
    type: String, 
    trim: true 
  },
  role: { 
    type: String, 
    enum: Object.values(UserRole),
    default: UserRole.USER 
  },
  status: { 
    type: String, 
    enum: Object.values(AccountStatus),
    default: AccountStatus.ACTIVE 
  },
  avatar: { 
    type: String 
  },
  phone: { 
    type: String 
  },
  addresses: [addressSchema], // Optional - remove if not needed
  passwordResetToken: { 
    type: String 
  },
  passwordResetExpires: { 
    type: Date 
  },
  passwordChangedAt: Date,
  emailVerified: { 
    type: Boolean, 
    default: false 
  },
  // OAuth providers
  googleId: {
    type: String,
    sparse: true,
    unique: true
  },
  facebookId: {
    type: String,
    sparse: true,
    unique: true
  },
  githubId: {
    type: String,
    sparse: true,
    unique: true
  },
  emailVerificationToken: { 
    type: String 
  },
  lastLogin: { 
    type: Date 
  },
  refreshToken: { 
    type: String 
  },
  // Additional generic fields
  preferences: {
    type: Map,
    of: Schema.Types.Mixed
  },
  metadata: {
    type: Map,
    of: Schema.Types.Mixed
  }
}, { 
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ emailVerificationToken: 1 });
userSchema.index({ passwordResetToken: 1 });
userSchema.index({ status: 1 });
userSchema.index({ googleId: 1, facebookId: 1, githubId: 1 });

// Virtual for full name
userSchema.virtual('fullName').get(function() {
  return `${this.firstName || ''} ${this.lastName || ''}`.trim() || this.username || this.email.split('@')[0];
});

// Don't return password and other sensitive fields by default
userSchema.set('toJSON', {
  transform: (_doc, ret) => {
    delete ret['password'];
    delete ret['refreshToken'];
    delete ret['passwordResetToken'];
    delete ret['passwordResetExpires'];
    delete ret['emailVerificationToken'];
    return ret;
  },
  virtuals: true
});

const User = model<UserDocument>('User', userSchema);

export default User;