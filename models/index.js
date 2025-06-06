const { Sequelize } = require('sequelize');
const UserModel = require('./user');
const ScreenDetailsModel = require('./screendetails');

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASS,
  {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
    //   ssl: {
    //     require: true,
    //     rejectUnauthorized: false
    //   }
    }
  }
);

const User = UserModel(sequelize);
const ScreenDetails = ScreenDetailsModel(sequelize);


module.exports = { sequelize, User, ScreenDetails};