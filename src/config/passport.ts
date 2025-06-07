import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import User from '../models/userModel';
import { config } from '../config/environment';
import { logger } from '../utils/logger';
import crypto from 'crypto';

// Google Strategy Configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: config.GOOGLE_CLIENT_ID as string,
      clientSecret: config.GOOGLE_CLIENT_SECRET as string,
      callbackURL: `${config.API_BASE_URL}/api/v1/auth/google/callback`,
      passReqToCallback: true, // Add this to access req in callback
    },
    async (_req: any, _accessToken: string, _refreshToken: string, profile: any, done: Function) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) {
          return done(new Error('No email found in Google profile'), null);
        }

        // Find or create user
        let user = await User.findOne({ 
          $or: [{ googleId: profile.id }, { email }] 
        });

        if (!user) {
          const randomPassword = crypto.randomBytes(20).toString('hex');
          user = await User.create({
            googleId: profile.id,
            email,
            firstName: profile.name?.givenName || profile.displayName?.split(' ')[0] || 'User',
            lastName: profile.name?.familyName || profile.displayName?.split(' ').slice(1).join(' ') || 'Unknown',
            password: randomPassword,
            emailVerified: true,
            avatar: profile.photos?.[0]?.value,
          });
        } else if (!user.googleId) {
          // Update existing user with Google ID
          user.googleId = profile.id;
          await user.save();
        }

        return done(null, user);
      } catch (error) {
        logger.error(`Google authentication error: ${error}`);
        return done(error, null);
      }
    }
  )
);

// Since we're using JWT, we can keep these simple
passport.serializeUser((user: any, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

export default passport;