Installation Instructions:

Get the latest version of the project files at
http://redmine.refreshcache.com/projects/cccevwpintegration

On your Arena system:

* Copy the Arena.Custom.WebUtils files from WP Integration project repository
  into your Arena install's bin folder
* Download the CCCEV Data Utils project and drop the Arena.Custom.Cccev.DataUtils
  files into your Arena installation's bin folder
* Copy the "AuthenticationService.asmx" web service into your Arena
  WebServices/Custom/CCCEV/Core folder


On your WordPress system:

* Copy the "arena-chms-authentication" folder to your WordPress installation's
  wp-content/plugins folder
* Log into your WordPress admin account. Under the "Plugins" section, you should
  see "Arena ChMS Authentication Provider" listed. Click "Activate". You should
  now see an "Arena Authentication" option under the "Settings" menu on the
  bottom/left.
* Enter the path to your web service in the *Arena Authentication Service Path* 
  (e.g. - "http://your-public-arena-install/Arena/WebServices/Custom/CCCEV/Core/AuthenticationService.asmx").
  The service should work fine over HTTPS if needed.
* Enter your *Arena Organization ID* (it's probably "1").
* Enter the *Arena Security Roles* you want to limit to (e.g. - Arena 
  Administrator, Blog Editor), or leave it blank if you want any Arena user to
  be able to log in.
* Enter the *Default WordPress Role* for newly created accounts (e.g. - Author).
  Note: When a user logs into WordPress that *does not* have an account yet,
  this plugin will create a WordPress user for them with the "Default WordPress
  Role" setting.