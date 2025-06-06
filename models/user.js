const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  return sequelize.define('User', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false,
        primaryKey: true
      },
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false
    },
    email: {
        type: DataTypes.STRING,
    },
    s3_bucket_name: {
      type: DataTypes.STRING,
    },
    azure_container_name: {
        type: DataTypes.STRING,
    },
    is_admin: {
      type: DataTypes.BOOLEAN,
      defaultValue: false
    },
    current_token: {
      type: DataTypes.STRING,
      allowNull: true
    },
    valid_columns: {
      type: DataTypes.JSONB, 
      allowNull: true
    },
    reset_token: DataTypes.TEXT,
    reset_token_expires: DataTypes.STRING
  });
};