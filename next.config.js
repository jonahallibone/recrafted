module.exports = {
  webpack: (config, { buildId, dev, isServer, defaultLoaders, webpack }) => {
    config.plugins.push(
      new webpack.DefinePlugin({ "global.GENTLY": false }), // This is because I use `superagent`, not for `knex`
      new webpack.IgnorePlugin(/mariasql/, /\/knex\//),
      new webpack.IgnorePlugin(/mssql/, /\/knex\//),
      new webpack.IgnorePlugin(/mysql/, /\/knex\//),
      new webpack.IgnorePlugin(/mysql2/, /\/knex\//),
      new webpack.IgnorePlugin(/oracle/, /\/knex\//),
      new webpack.IgnorePlugin(/oracledb/, /\/knex\//),
      new webpack.IgnorePlugin(/pg-query-stream/, /\/knex\//),
      new webpack.IgnorePlugin(/sqlite3/, /\/knex\//),
      new webpack.IgnorePlugin(/strong-oracle/, /\/knex\//),
      new webpack.IgnorePlugin(/pg-native/, /\/pg\//)
    );

    // Important: return the modified config
    return config;
  },
};
