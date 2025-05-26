import passport from 'passport';
import { Strategy as GoogleStrategy, Profile as GoogleProfile, StrategyOptions } from 'passport-google-oauth20';
import User from '../models/userModel.js';
import { config } from '../config/environment.js';
import { logger } from '../utils/logger.js';
import crypto from 'crypto';
// import { IUser } from '../types/userTypes.js';
// import { HydratedDocument } from 'mongoose';

// Google Strategy Configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: config.GOOGLE_CLIENT_ID,
      clientSecret: config.GOOGLE_CLIENT_SECRET,
      callbackURL: `${config.API_BASE_URL}/api/v1/users/auth/google/callback`,
      scope: ['profile', 'email'],
    } as StrategyOptions,
    async (
      _accessToken: string,
      _refreshToken: string,
      profile: GoogleProfile,
      done: (error: any, user?: any) => void
    ) => {
      try {
        const email = profile.emails?.[0]?.value || `${profile.id}@googleuser.com`;

        const firstName = profile.name?.givenName || profile.displayName?.split(' ')[0] || 'User';
        const lastName =
          profile.name?.familyName ||
          (profile.displayName?.split(' ').length > 1
            ? profile.displayName.split(' ').slice(1).join(' ')
            : 'Unknown');

        const existingUser = await User.findOne({
          $or: [{ googleId: profile.id }, { email }],
        });

        if (existingUser) {
          if (!existingUser.googleId) {
            existingUser.googleId = profile.id;
            await existingUser.save();
          }
          return done(null, existingUser);
        }

        const randomPassword = crypto.randomBytes(20).toString('hex');

        const newUser = await User.create({
          googleId: profile.id,
          email,
          firstName,
          lastName,
          password: randomPassword,
          emailVerified: true,
        });

        return done(null, newUser);
      } catch (error) {
        logger.error(`Google authentication error: ${error}`);
        return done(error as Error);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user: Express.User, done) => {
//   const userId = (user as IUser)._id.toString();
  done(null, user._id?.toString());
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

export default passport;
