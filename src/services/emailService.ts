// src/services/email.service.ts
import nodemailer from 'nodemailer';
import { config } from '@/config/environment';
import { logger } from '@/utils/logger';

// Create reusable transporter object using SMTP transport
const transporter = nodemailer.createTransporter({
  service: config.EMAIL_SERVICE || 'gmail',
  host: config.EMAIL_HOST,
  port: parseInt(config.EMAIL_PORT || '587'),
  secure: config.EMAIL_SECURE === 'true', // true for 465, false for other ports
  auth: {
    user: config.EMAIL_USER,
    pass: config.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false // For self-signed certificates
  }
});

export const emailService = {
  /**
   * Base email sending function
   */
  sendEmail: async (to: string, subject: string, html: string, text?: string): Promise<void> => {
    const startTime = Date.now();
    
    try {
      const mailOptions = {
        from: `"${config.APP_NAME}" <${config.EMAIL_USER}>`,
        to,
        subject,
        text: text || html.replace(/<[^>]*>/g, ''), // Fallback text version
        html
      };

      const info = await transporter.sendMail(mailOptions);
      const duration = Date.now() - startTime;
      
      logger.email('send', to, true, info.messageId);
      logger.performance('email_send', duration, { subject, to });
      
    } catch (error) {
      const duration = Date.now() - startTime;
      logger.email('send', to, false, undefined, error);
      logger.performance('email_send_failed', duration, { subject, to, error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  },

  /**
   * Send email verification with OTP
   */
  sendVerificationEmail: async (to: string, name: string, otp: string): Promise<void> => {
    logger.info('Sending verification email', { to, name });
    
    const subject = `Verify Your ${config.APP_NAME} Account`;
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #2c3e50;">Email Verification</h2>
        <p>Hi ${name},</p>
        <p>Thank you for registering with ${config.APP_NAME}! To complete your registration, please verify your email address.</p>
        
        <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; text-align: center;">
          <p style="font-size: 18px; margin-bottom: 10px;">Your verification code is:</p>
          <div style="font-size: 32px; font-weight: bold; color: #007bff; letter-spacing: 5px; font-family: monospace;">
            ${otp}
          </div>
          <p style="color: #6c757d; margin-top: 10px;">This code will expire in 10 minutes</p>
        </div>
        
        <p>If you didn't create an account with us, please ignore this email.</p>
        
        <p style="margin-top: 30px;">Best regards,<br>The ${config.APP_NAME} Team</p>
      </div>
    `;

    await emailService.sendEmail(to, subject, html);
  },

  /**
   * Send welcome email to new user
   */
  sendWelcomeEmail: async (to: string, name: string): Promise<void> => {
    logger.info('Sending welcome email', { to, name });
    
    const subject = `Welcome to ${config.APP_NAME}!`;
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #2c3e50;">Welcome to ${config.APP_NAME}, ${name}!</h2>
        <p>Hello ${name},</p>
        <p>Congratulations! Your email has been successfully verified and your account is now active.</p>
        
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
          <p style="font-weight: bold;">You can now access all features:</p>
          <ul style="margin-top: 10px;">
            <li>Complete access to your dashboard</li>
            <li>Update your profile information</li>
            <li>Change your password anytime</li>
            <li>Full access to all platform features</li>
          </ul>
        </div>

        <div style="text-align: center; margin: 30px 0;">
          <a href="${config.CLIENT_URL}/dashboard" 
             style="background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Access Your Dashboard
          </a>
        </div>
        
        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
        
        <p style="margin-top: 30px;">Welcome aboard!</p>
        <p>Best regards,<br>The ${config.APP_NAME} Team</p>
      </div>
    `;
    
    await emailService.sendEmail(to, subject, html);
  },

  /**
   * Send password reset email
   */
  sendPasswordResetEmail: async (to: string, name: string, resetToken: string): Promise<void> => {
    logger.info('Sending password reset email', { to, name });
    logger.security('password_reset_requested', undefined, undefined, { email: to, name });
    
    const subject = 'Password Reset Request';
    const resetUrl = `${config.CLIENT_URL}/reset-password?token=${resetToken}`;
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #2c3e50;">Password Reset Request</h2>
        <p>Hello ${name},</p>
        <p>We received a request to reset your password for your ${config.APP_NAME} account.</p>
        
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" 
             style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
            Reset Your Password
          </a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 4px;">
          ${resetUrl}
        </p>
        
        <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0; color: #856404;">
            <strong>Important:</strong> This link will expire in 1 hour for security reasons.
          </p>
        </div>
        
        <p>If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
        
        <p style="margin-top: 30px;">Best regards,<br>The ${config.APP_NAME} Team</p>
      </div>
    `;
    
    await emailService.sendEmail(to, subject, html);
  },

  /**
   * Send password change notification
   */
  sendPasswordChangeNotification: async (to: string, name: string): Promise<void> => {
    logger.info('Sending password change notification', { to, name });
    logger.security('password_changed', undefined, undefined, { email: to, name });
    
    const subject = 'Password Changed Successfully';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #2c3e50;">Password Change Notification</h2>
        <p>Hello ${name},</p>
        <p>This is to confirm that your account password was successfully changed on ${new Date().toLocaleString()}.</p>
        
        <div style="background-color: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0; color: #155724;">
            <strong>✓ Your password has been updated successfully</strong>
          </p>
        </div>
        
        <div style="background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <p style="margin: 0; color: #721c24;">
            <strong>Security Alert:</strong> If you didn't make this change, please contact our support team immediately.
          </p>
        </div>
        
        <p>For your security:</p>
        <ul>
          <li>Never share your password with anyone</li>
          <li>Use a strong, unique password</li>
          <li>Log out from public or shared devices</li>
        </ul>
        
        <p style="margin-top: 30px;">Best regards,<br>The ${config.APP_NAME} Team</p>
      </div>
    `;
    
    await emailService.sendEmail(to, subject, html);
  },

  /**
   * Send account status change notification
   */
  sendAccountStatusNotification: async (to: string, name: string, status: string, reason?: string): Promise<void> => {
    logger.info('Sending account status notification', { to, name, status, reason });
    logger.security('account_status_changed', undefined, undefined, { email: to, name, status, reason });
    
    const subject = `Account Status Update - ${config.APP_NAME}`;
    const statusColors: Record<string, string> = {
      active: '#28a745',
      suspended: '#ffc107',
      inactive: '#6c757d',
      banned: '#dc3545',
      pending: '#17a2b8'
    };
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #2c3e50;">Account Status Update</h2>
        <p>Hello ${name},</p>
        <p>The status of your ${config.APP_NAME} account has been updated to:</p>
        
        <div style="background-color: ${statusColors[status.toLowerCase()] || '#f8f9fa'}; 
                    color: ${['suspended', 'active'].includes(status.toLowerCase()) ? '#212529' : 'white'};
                    padding: 15px; border-radius: 5px; margin: 15px 0; text-align: center;">
          <h3 style="margin: 0; text-transform: capitalize;">${status}</h3>
        </div>
        
        ${reason ? `<p><strong>Reason:</strong> ${reason}</p>` : ''}
        
        ${status.toLowerCase() === 'active' ? `
          <p>Your account is now fully active and you can access all features.</p>
          <div style="text-align: center; margin: 20px 0;">
            <a href="${config.CLIENT_URL}/login" 
               style="background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
              Login to Your Account
            </a>
          </div>
        ` : ''}
        
        ${status.toLowerCase() === 'suspended' ? `
          <div style="background-color: #fff3cd; border-left: 5px solid #ffeeba; padding: 10px; margin: 15px 0;">
            <p style="margin: 0;">Your account has been temporarily suspended. During this time, you won't be able to access certain features.</p>
          </div>
          <p>If you believe this is a mistake or would like to appeal, please contact our support team.</p>
        ` : ''}
        
        ${status.toLowerCase() === 'banned' ? `
          <div style="background-color: #f8d7da; border-left: 5px solid #f5c6cb; padding: 10px; margin: 15px 0;">
            <p style="margin: 0;">Your account has been permanently banned from ${config.APP_NAME} due to violations of our terms of service.</p>
          </div>
          <p>All associated data will be permanently deleted after 30 days in accordance with our data retention policy.</p>
        ` : ''}
        
        <p style="margin-top: 30px;">Best regards,<br>The ${config.APP_NAME} Team</p>
      </div>
    `;
    
    await emailService.sendEmail(to, subject, html);
  },

  /**
   * Send order confirmation email
   */
  sendOrderConfirmationEmail: async (
    to: string,
    name: string,
    orderId: string,
    orderItems: Array<{
      name: string;
      quantity: number;
      price: number;
      image?: string;
    }>,
    totalAmount: number,
    shippingAddress?: any
  ): Promise<void> => {
    logger.info('Sending order confirmation email', { to, name, orderId, totalAmount });
    
    const subject = `Order Confirmation #${orderId}`;
    
    // Generate order items HTML
    const itemsHtml = orderItems.map(item => `
      <tr>
        <td style="padding: 10px; border-bottom: 1px solid #e0e0e0; vertical-align: top;">
          ${item.image ? `<img src="${item.image}" alt="${item.name}" style="width: 60px; height: 60px; object-fit: cover; margin-right: 10px;">` : ''}
          ${item.name}
        </td>
        <td style="padding: 10px; border-bottom: 1px solid #e0e0e0; text-align: center;">${item.quantity}</td>
        <td style="padding: 10px; border-bottom: 1px solid #e0e0e0; text-align: right;">$${item.price.toFixed(2)}</td>
        <td style="padding: 10px; border-bottom: 1px solid #e0e0e0; text-align: right;">$${(item.price * item.quantity).toFixed(2)}</td>
      </tr>
    `).join('');
    
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #2c3e50;">Order Confirmation #${orderId}</h2>
        <p>Hello ${name},</p>
        <p>Thank you for your order! We've received your order and are processing it now.</p>
        
        <div style="margin: 20px 0;">
          <h3 style="color: #2c3e50; margin-bottom: 10px;">Order Summary</h3>
          <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
            <thead>
              <tr style="background-color: #f8f9fa;">
                <th style="padding: 10px; text-align: left; border-bottom: 2px solid #e0e0e0;">Product</th>
                <th style="padding: 10px; text-align: center; border-bottom: 2px solid #e0e0e0;">Qty</th>
                <th style="padding: 10px; text-align: right; border-bottom: 2px solid #e0e0e0;">Price</th>
                <th style="padding: 10px; text-align: right; border-bottom: 2px solid #e0e0e0;">Total</th>
              </tr>
            </thead>
            <tbody>
              ${itemsHtml}
            </tbody>
            <tfoot>
              <tr>
                <td colspan="3" style="padding: 10px; text-align: right; font-weight: bold; border-top: 2px solid #e0e0e0;">Total:</td>
                <td style="padding: 10px; text-align: right; font-weight: bold; border-top: 2px solid #e0e0e0;">$${totalAmount.toFixed(2)}</td>
              </tr>
            </tfoot>
          </table>
        </div>
        
        ${shippingAddress ? `
          <div style="margin: 20px 0;">
            <h3 style="color: #2c3e50; margin-bottom: 10px;">Shipping Details</h3>
            <p>${shippingAddress.fullName}</p>
            <p>${shippingAddress.addressLine1}</p>
            ${shippingAddress.addressLine2 ? `<p>${shippingAddress.addressLine2}</p>` : ''}
            <p>${shippingAddress.city}, ${shippingAddress.state} ${shippingAddress.postalCode}</p>
            <p>${shippingAddress.country}</p>
          </div>
        ` : ''}
        
        <p>You will receive another email when your order has shipped.</p>
        <p>If you have any questions about your order, please contact our customer service.</p>
        
        <p style="margin-top: 30px;">Thank you for shopping with us!</p>
        <p>Best regards,<br>The ${config.APP_NAME} Team</p>
      </div>
    `;
    
    await emailService.sendEmail(to, subject, html);
  },

  /**
   * Send contact form submission
   */
  sendContactFormSubmission: async (
    from: string,
    name: string,
    subject: string,
    message: string
  ): Promise<void> => {
    logger.info('Sending contact form submission', { from, name, subject });
    
    const adminSubject = `New Contact Form Submission: ${subject}`;
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
        <h2 style="color: #2c3e50;">New Contact Form Submission</h2>
        <p><strong>From:</strong> ${name} &lt;${from}&gt;</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 15px;">
          <p style="white-space: pre-wrap;">${message}</p>
        </div>
        <p style="margin-top: 20px;">Please respond to this inquiry as soon as possible.</p>
      </div>
    `;
    
    await emailService.sendEmail(config.CONTACT_EMAIL || config.EMAIL_USER, adminSubject, html);
  }
};