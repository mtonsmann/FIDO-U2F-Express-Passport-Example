/*'use strict';
*
*//**
* * Module dependencies.
* *//*
*
*const home = require('../app/controllers/home');
*
*//**
* * Expose
* *//*
*
*module.exports = function (app, passport) {
*
*  app.get('/', home.index);
*
*  /**
*   * Error handling
*   *//*
*
*  app.use(function (err, req, res, next) {
*    // treat as 404
*    if (err.message
*      && (~err.message.indexOf('not found')
*      || (~err.message.indexOf('Cast to ObjectId failed')))) {
*      return next();
*    }
*    console.error(err.stack);
*    // error page
*    res.status(500).render('500', { error: err.stack });
*  });
*
*  // assume 404 since no middleware responded
*  app.use(function (req, res, next) {
*    res.status(404).render('404', {
*      url: req.originalUrl,
*      error: 'Not found'
*    });
*  });
*};
*/

'use strict';

/*
 * Module dependencies.
 */

const users = require('../app/controllers/users');
const home = require('../app/controllers/home');
//const articles = require('../app/controllers/articles');
//const comments = require('../app/controllers/comments');
//const tags = require('../app/controllers/tags');
const auth = require('./middlewares/authorization');

/**
 * Route middlewares
 */

//const articleAuth = [auth.requiresLogin, auth.article.hasAuthorization];
//const commentAuth = [auth.requiresLogin, auth.comment.hasAuthorization];

const fail = {
  failureRedirect: '/login'
};

/**
 * Expose routes
 */

module.exports = function (app, passport) {
  const pauth = passport.authenticate.bind(passport);
  
  // user routes
  app.get('/u2f-api.js', users.api);
  app.get('/login', users.login);
  app.get('/2faCheck', auth.requiresLogin, users.twofacheck);
  app.get('/signup', users.signup);
  app.get('/setup2FA', users.setup2fa);
  app.get('/registerU2F', auth.requiresLogin, users.registerGet);
  app.post('/registerU2F', auth.requiresLogin, users.registerPost);
  app.get('/authenticateU2F', auth.requiresLogin, users.authenticateGet);
  app.post('/authenticateU2F', auth.requiresLogin, users.authenticatePost);
  app.get('/logout', users.logout);
  app.post('/users', users.create);
  app.post('/users/session',
    pauth('local', {
      failureRedirect: '/login',
      failureFlash: 'Invalid email or password.'
    }), users.session);
  app.get('/users/:userId', auth.requires2FA, users.show);

  app.param('userId', users.load);

  // article routes
  /*app.param('id', articles.load);
  app.get('/articles', articles.index);
  app.get('/articles/new', auth.requiresLogin, articles.new);
  app.post('/articles', auth.requiresLogin, articles.create);
  app.get('/articles/:id', articles.show);
  app.get('/articles/:id/edit', articleAuth, articles.edit);
  app.put('/articles/:id', articleAuth, articles.update);
  app.delete('/articles/:id', articleAuth, articles.destroy);
  */
  // home route
  app.get('/', home.index);

  // comment routes
  //app.param('commentId', comments.load);
  //app.post('/articles/:id/comments', auth.requiresLogin, comments.create);
  //app.get('/articles/:id/comments', auth.requiresLogin, comments.create);
  //app.delete('/articles/:id/comments/:commentId', commentAuth, comments.destroy);

  // tag routes
  //app.get('/tags/:tag', tags.index);


  /**
   * Error handling
   */

  app.use(function (err, req, res, next) {
    // treat as 404
    if (err.message
      && (~err.message.indexOf('not found')
      || (~err.message.indexOf('Cast to ObjectId failed')))) {
      return next();
    }

    console.error(err.stack);

    if (err.stack.includes('ValidationError')) {
      res.status(422).render('422', { error: err.stack });
      return;
    }

    // error page
    res.status(500).render('500', { error: err.stack });
  });

  // assume 404 since no middleware responded
  app.use(function (req, res) {
    const payload = {
      url: req.originalUrl,
      error: 'Not found'
    };
    if (req.accepts('json')) return res.status(404).json(payload);
    res.status(404).render('404', payload);
  });
};
