'use strict';
const bcrypt = require('bcryptjs');
const mongoose_delete = require('mongoose-delete');
module.exports = (mongoose, uuid) => {
  let schema = mongoose.Schema(
    {
      _id: {
        type: String,
        auto: true,
        default: () => uuid.v4(),
        trim: true,
        lowercase: true,
      },
      name: {
        type: String,
        index: true,
        required: true,
        trim: true,
      },
      email: {
        type: String,
        lowercase: true,
        index: true,
        trim: true,
      },
      phone: {
        type: String,
        index: true,
        required: true,
        trim: true,
      },
      password: { type: String, trim: true, select: true },
      status: Boolean,
      verified: {
        type: Boolean,
        index: true,
        trim: true,
      },
      loginAttempts: {
        type: Number,
        default: 0,
      },
      blockExpires: {
        type: Date,
        default: Date.now,
      },
    },
    { timestamps: true },
  );

  schema.plugin(mongoose_delete, { deletedAt: true });

  schema.path('email').validate((val) => {
    let emailRegex =
      /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return emailRegex.test(val);
  }, 'Invalid e-mail.');

  /*schema.path("_id").validate(function (v) {
      console.log("validating: " + JSON.stringify(v));
      return validator.isUUID(v);
  }, "ID is not a valid GUID: {VALUE}");*/

  schema.pre('save', async function (next) {
    let tenant = this;
    const SALT_FACTOR = 10;

    // If tenant is not new or the password is not modified
    if (!tenant.isModified('password')) {
      return next();
    }

    if (this.isModified('password') || this.isNew) {
      // Encrypt password before saving to database
      let salt = await bcrypt.genSalt(SALT_FACTOR);
      tenant.password = await bcrypt.hash(tenant.password, salt);
    }
    if (tenant.isNew) {
      tenant.createAt = tenant.updateAt = Date.now();
    } else {
      tenant.updateAt = Date.now();
    }

    if (tenant.loginAttempts >= 5) {
      tenant.loginAttempts = 0;
      tenant.blockExpires = new Date(Date.now() + 60 * 5 * 1000);
    }

    let emailCriteria = {
      email: tenant.email,
      verified: true,
      deleted: false,
      status: false,
      _id: { $ne: tenant._id },
    };
    await Tenant.findOne(emailCriteria, 'email', async function (err, results) {
      if (err) {
        next(err);
      } else if (results) {
        //console.warn('results', results);
        tenant.invalidate('email', 'Email must be unique');
        next(new Error('Email must be unique'));
      } else {
        //console.log('Email unique check pass');
        next();
      }
    });

    let phoneCriteria = {
      phone: tenant.phone,
      verified: true,
      deleted: false,
      status: false,
      _id: { $ne: tenant._id },
    };
    await Tenant.findOne(phoneCriteria, 'phone', async function (err, results) {
      if (err) {
        next(err);
      } else if (results) {
        //console.warn('results', results);
        tenant.invalidate('phone', 'Phone number must be unique');
        next(new Error('Phone number must be unique'));
      } else {
        //console.log('Phone unique check pass');
        next();
      }
    });
  });

  schema.method('toJSON', function () {
    const { __v, _id, ...object } = this.toObject();
    object.id = _id;
    object.v = __v;
    return object;
  });

  // Virtual for tenant's full name
  /*schema.virtual('fullName').get(function () {
    return this.firstName + ' ' + this.lastName;
  });*/

  schema.methods.comparePassword = async function (candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
  };

  const Tenant = mongoose.model('Tenant', schema);
  return Tenant;
};
