'use strict';
/*!
 * Module dependencies
 */
const iterations = 1000;
const mongoose = require('mongoose');
const crypto = require('crypto');

const Schema = mongoose.Schema;

/**
 * User schema
 */

const deviceRegistrationSchema = new Schema({
  keyHandle: {type: String, default: ''},
  publicKey: {type: String, default: ''},
  certificate: {type: String, default: ''}
});

const UserSchema = new Schema({
  name: { type: String, default: '' },
  email: { type: String, default: '' },
  username: { type: String, default: '' },
  hashed_password: { type: String, default: '' },
  salt: { type: String, default: '' },
  deviceRegistration: {
    type: deviceRegistrationSchema,
    required: false
  }
});



const validatePresenceOf = value => value && value.length;

/**
  * Virtuals
  */

UserSchema
  .virtual('password')
  .set(function (password) {
    this._password = password;
    this.salt = this.makeSalt();
    this.hashed_password = this.encryptPassword(password);
  })
  .get(function () {
    return this._password;
});

/**
 * Validations
 */

UserSchema.path('name').validate(function (name) {
  return name.length;
}, 'Name cannot be blank');

UserSchema.path('email').validate(function (email) {
  return email.length;
}, 'Email cannot be blank');

UserSchema.path('email').validate(function (email, fn) {
  const User = mongoose.model('User');

  // Check only when it is a new user or when email field is modified
  if (this.isNew || this.isModified('email')) {
    User.find({ email: email }).exec(function (err, users) {
      fn(!err && users.length === 0);
    });
  } else fn(true);
}, 'Email already exists');

UserSchema.path('username').validate(function (username) {
  return username.length;
}, 'Username cannot be blank');

UserSchema.path('hashed_password').validate(function (hashed_password) {
  return hashed_password.length && this._password.length;
}, 'Password cannot be blank');
 

deviceRegistrationSchema.path('keyHandle').validate(function (keyHandle) {
    return true;
}, 'Always true');

deviceRegistrationSchema.path('publicKey').validate(function (publicKey) {
    return true;
}, 'Always true');

deviceRegistrationSchema.path('certificate').validate(function (certificate) {
    return true;
}, 'Always true');


/**
 * Pre-save hook
 */

UserSchema.pre('save', function (next) {
  if (!this.isNew) return next();

  if (!validatePresenceOf(this.password)) {
    next(new Error('Invalid password'));
  } else {
    next();
  }
});


/**
 * Methods
 */

UserSchema.methods = {

  add2FA: function (registration) {
    this.deviceRegistration = registration;
//    console.log('test from within');
    
//    return this.username;
  },  

  /**
   * Authenticate - check if the passwords are the same
   *
   * @param {String} plainText
   * @return {Boolean}
   * @api public
   */

  authenticate: function (plainText) {
    return this.encryptPassword(plainText) === this.hashed_password;
  },

  /**
   * Make salt
   *
   * @return {String}
   * @api public
   */

  makeSalt: function () {
    //return Math.round((new Date().valueOf() * Math.random())) + '';
    return crypto.randomBytes(128).toString('base64');
  },

  /**
   * Encrypt password
   *
   * @param {String} password
   * @return {String}
   * @api public
   */

  encryptPassword: function (password) {
    if (!password) return '';
    try {
      //return crypto
      //  .createHmac('sha1', this.salt)
      // .update(password)
      //  .digest('hex');
      // use a correct hashing algorithm instead of sha1
      const key = crypto.pbkdf2Sync(password, this.salt, 100000, 512, 'sha512');
      return key.toString('hex');
    } catch (err) {
      return '';
    }
  },
};

/**
 * Statics
 */

UserSchema.statics = {

  /**
   * Load
   *
   * @param {Object} options
   * @param {Function} cb
   * @api private
   */

  load: function (options, cb) {
    options.select = options.select || 'name username';
    return this.findOne(options.criteria)
      .select(options.select)
      .exec(cb);
  }
};

mongoose.model('User', UserSchema);
