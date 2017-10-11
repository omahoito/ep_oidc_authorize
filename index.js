var request = require('request');
var log4js = require('log4js');

log4js.configure({
    appenders: { authorize: { type: 'file', filename: 'ep_oidc_authorize.log' } },
    categories: { default: { appenders: ['authorize'], level: 'debug' } }
});

var logger = log4js.getLogger('authorize');

exports.authorize = function (hook_name, context, cb) {
    logger.debug('ep_oidc_authorize: Authorize in action');
    
  if(context.resource == "/auth/callback")
  {
      logger.debug('ep_oidc_authorize: Callback passed');
    return cb([true]);
  }
  if (context.req.session.passport) {

      //Only authorize ones starting with /p/ = public or g. = group
      if (!context.resource.startsWith("/p/") && !context.resource.startsWith("/g.")) {
          logger.debug("ep_oidc_authorize: Not interested authorizing resource:" + context.resource);
          return cb([true]);
      }

      try {
          var authorizeUrl = process.env.ETHERPAD_AUTH_URL;
          authorizeUrl += "?user_id=" + context.req.session.passport.user.sub;
          authorizeUrl += "&resource=" + context.resource;
          
          request.get({
              url: authorizeUrl,
              json: true
          }, function (err, res, data) {
              //Error
              if (err) {
                  logger.error("ep_oidc_authorize: Error calling Authorize: " + err);
                  return cb([false]);
              }

              //Success
              logger.debug("ep_oidc_authorize: Authorize returned " + res.statusCode + " " + res.statusMessage);


              if (res.statusCode == 200 && body.redirectUrl == null){
                  return cb([true]);
              }
              //Authorize created a new pad on the backend, redirect to pad url given
              else if (res.statusCode == 200 && body.redirectUrl != null) {
                  context.res.redirect(body.redirectUrl);
              }
              else
              {
                  //Return JSON response for unauthorized access
                  context.res.writeHead(200, { "Content-Type": "application/json" });
                  context.res.end(JSON.stringify({ status: "Permission denied." }));
              }
                  
                  
          });

      } catch (e) {
          logger.error("ep_oidc_authorize: Error:" + e.message);
          return cb([false]); 
      }
  } 
  else {
    logger.debug('ep_oidc_authorize: auth not completed');
    return cb([false]);
  }
};

