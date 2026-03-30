require('dotenv').config();
var express = require('express');
var logger = require('morgan');

var indexRouter = require('./routes/index');

var app = express();

app.use(logger('dev'));

app.use('/', indexRouter);

// catch 404
app.use(function(req, res) {
  res.status(404).json({error: 'Not found'});
});

// error handler
app.use(function(err, req, res, next) {
  res.status(err.status || 500).json({error: err.message || 'Internal Server Error'});
});

module.exports = app;
