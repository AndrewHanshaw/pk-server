require('dotenv').config();
var express = require('express');
var logger = require('morgan');

var indexRouter = require('./routes/index');

var app = express();

// Trust the first proxy (Vercel) so req.ip is the real client IP from X-Forwarded-For.
// The rate limiter keys off req.ip, so without this every client would share Vercel's edge IP and one bucket.
app.set('trust proxy', 1);

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
