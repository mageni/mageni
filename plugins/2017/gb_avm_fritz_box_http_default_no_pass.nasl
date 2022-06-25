###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_http_default_no_pass.nasl 11412 2018-09-16 10:21:40Z cfischer $
#
# AVM FRITZ!Box Default / no Password (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:avm:fritz%21_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108042");
  script_version("$Revision: 11412 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-16 12:21:40 +0200 (Sun, 16 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-10 15:00:00 +0100 (Tue, 10 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AVM FRITZ!Box Default / no Password (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_avm_fritz_box_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("avm_fritz_box/http/detected");

  script_tag(name:"summary", value:"This script detects if the device has:

  - a default password set

  - no password set");

  script_tag(name:"vuldetect", value:"Check if the device is not password protected or if it is
  possible to login with a default password.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");

  script_tag(name:"solution", value:"Set a password or change the identified default password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

# nb: Keep http_send_recv for all request as it seems http_keepalive_send_recv doesn't return all data on this boxes

# Creating the response, example from js:
# var challenge = "769b3d3f"; var str = challenge + "-" + makeDots(pw); var response = challenge + "-" + hex_md5(str);
function create_response( challenge, credential ) {

  local_var challenge, response, str, credential;

  str = challenge + "-" + credential;
  # Used 16 bits (unicode) per input character which is passed to the MD5 function in md5.js
  response = challenge + "-" + hexstr( MD5( ascii2unicode( data:str ) ) );

  return response;
}

function do_webcm_post_req( port, posturl, sid, dir ) {

  local_var port, posturl, sid, dir, time, postdata, req, res;

  time = unixtime();

  if( sid ) {
    postdata = "sid=" + sid + "&getpage=..%2Fhtml%2Flogincheck.html&errorpage=..%2Fhtml%2Findex.html" +
               "&var%3Alang=de&var%3Apagename=home&var%3Amenu=home&var%3Amenutitle=Home" +
               "&time%3Asettings%2Ftime=" + time + "%2C-60";
  } else {
    postdata = "getpage=..%2Fhtml%2Fde%2Fmenus%2Fmenu2.html&errorpage=..%2Fhtml%2Findex.html&var%3Alang=de" +
               "&var%3Apagename=home&var%3Amenu=home&time%3Asettings%2Ftime=" + time + "%2C-60";
  }

  req = http_post_req( port:port, url:posturl, data:postdata,
                       accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                       add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded",
                                               "Upgrade-Insecure-Requests", "1",
                                               "Referer", report_vuln_url( port:port, url:dir + "/cgi-bin/webcm?getpage=../html/index_inhalt.html", url_only:TRUE ) ) );
  res = http_send_recv( port:port, data:req );
  return res;
}

credentials = make_list( "1234",
                         "0000",
                         "admin",
                         "password",
                         "passwort" );

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

# e.g. FonWLAN 7113 with 60.04.48, FonWLAN 7240 with 73.04.48, Fon with 06.04.33
url = dir + "/cgi-bin/webcm?getpage=../html/index_inhalt.html";
req = http_get( port:port, item:url );
res = http_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && ( '<form method="POST" action="../cgi-bin/webcm"' >< res || '<form method="GET" action="../cgi-bin/webcm"' >< res ) ) {

  posturl = dir + "/cgi-bin/webcm";

  sid = eregmatch( pattern:'sid" value="([a-z0-9]+)" id="uiPostSid', string:res );
  if( ! isnull( sid[1] ) ) {

    res = do_webcm_post_req( port:port, posturl:posturl, sid:sid[1], dir:dir );

    # With password reminder but no password set yet
    if( res =~ "^HTTP/1\.[01] 200" && '<label for="uiViewUsePassword">' >< res && '<label for="uiViewPasswordConfirm">' >< res && '<label for="uiShowReminder">' >< res ) {
      report = "The URL " + report_vuln_url( port:port, url:"/", url_only:TRUE ) + " has no password set.";
      security_message( port:port, data:report );
      exit( 0 );
    }
  # e.g. Fon with 06.04.33 doesn't have a sid
  } else {
    res = do_webcm_post_req( port:port, posturl:posturl, dir:dir );
    # Without a password password set yet
    if( res =~ "^HTTP/1\.[01] 200" && '<p class="ac">FRITZ!Box' >< res && "Firmware-Version" >< res ) {
      report = "The URL " + report_vuln_url( port:port, url:"/", url_only:TRUE ) + " has no password set.";
      security_message( port:port, data:report );
      exit( 0 );
    }
  }

  # counter for sleeps between login tries.
  # The box will lock us out with too many tries in a row.
  sleepsecs = 1;

  foreach credential( credentials ) {

    url = dir + "/cgi-bin/webcm?getpage=../html/index_inhalt.html";
    req = http_get( port:port, item:url );
    res = http_send_recv( port:port, data:req );

    sid = eregmatch( pattern:'sid" value="([a-z0-9]+)" id="uiPostSid', string:res );
    if( ! isnull( sid[1] ) ) {

      res = do_webcm_post_req( port:port, posturl:posturl, sid:sid[1], dir:dir );

      # The response contains a challenge if a password is set. This is needed later.
      challenge = eregmatch( pattern:'var challenge = "([a-z0-9]+)";', string:res );
      if( ! isnull( challenge[1] ) ) {

        response = create_response( challenge:challenge[1], credential:credential );
        postdata = "sid=0000000000000000&getpage=..%2Fhtml%2Fde%2Fmenus%2Fmenu2.html&errorpage=..%2Fhtml%2Findex.html" +
                   "&var%3Alang=de&var%3Apagename=home&var%3Amenu=home&login%3Acommand%2Fresponse=" + response;
        req = http_post_req( port:port, url:posturl, data:postdata,
                             accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                             add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded",
                                                     "Upgrade-Insecure-Requests", "1",
                                                     "Referer", report_vuln_url( port:port, url:dir + "/cgi-bin/webcm", url_only:TRUE ) ) );
        res = http_send_recv( port:port, data:req );

        if( res =~ "HTTP/1\.. 200" && ( '<img src="../html/de/images/Logout.gif"></a>' >< res || 'value="../html/confirm_logout.html">' >< res ) ) {
          report = "It was possible to login at " + report_vuln_url( port:port, url:"/", url_only:TRUE ) + " with the password '" + credential + "'.";
          security_message( port:port, data:report );
          exit( 0 );
        }
      }
      sleepsecs *= 2;
      sleep( sleepsecs );
    # e.g. Fon with 06.04.33 doesn't have a sid
    } else {
      postdata = "getpage=..%2Fhtml%2Fde%2Fmenus%2Fmenu2.html&errorpage=..%2Fhtml%2Findex.html&var%3Alang=de&var%3Apagename=home" +
                 "&var%3Amenu=home&login%3Acommand%2Fpassword=" + credential;
      req = http_post_req( port:port, url:"/cgi-bin/webcm", data:postdata,
                           accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                           add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded",
                                                   "Upgrade-Insecure-Requests", "1",
                                                   "Referer", report_vuln_url( port:port, url:dir + "/cgi-bin/webcm", url_only:TRUE ) ) );
      res = http_send_recv( port:port, data:req );
      if( res =~ "^HTTP/1\.[01] 200" && '<p class="ac">FRITZ!Box' >< res && "Firmware-Version" >< res ) {
        report = "It was possible to login at " + report_vuln_url( port:port, url:"/", url_only:TRUE ) + " with the password '" + credential + "'.";
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

# e.g. FonWLAN 7240 with 73.05.05 or 73.05.58 firmware
url = dir + "/home/home.lua";
req = http_get( port:port, item:url );
res = http_send_recv( port:port, data:req );

if( res =~ "HTTP/1\.. 200" && ( '<img src="/css/default/images/icon_abmelden.gif">' >< res || '<li><a href="/net/network_user_devices.lua?sid=' >< res ||
                                '<li><a href="/system/syslog.lua?sid=' >< res ) ) {
  report = "The URL " + report_vuln_url( port:port, url:url, url_only:TRUE ) + " has no password set.";
  security_message( port:port, data:report );
  exit( 0 );
}

url = dir + "/login.lua";
req = http_get( port:port, item:url );
res = http_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && ( 'method="POST" action="/login.lua"' >< res || 'method="post" action="/login.lua"' >< res ) ) {

  # First try if no password is set
  url = dir + "/logincheck.lua";
  req = http_get( port:port, item:url );
  res = http_send_recv( port:port, data:req );

  if( res =~ "^HTTP/1\.[01] 303" && "/no_password.lua?sid=" >< res ) {

    sid = eregmatch( pattern:"/no_password\.lua\?sid=([a-z0-9]+)", string:res );
    if( ! isnull( sid[1] ) ) {
      url = "/home/home.lua?sid=" + sid[1];
      req = http_get( port:port, item:url );
      res = http_send_recv( port:port, data:req );

      if( res =~ "^HTTP/1\.[01] 200" && ( '<img src="/css/default/images/icon_abmelden.gif">' >< res || '<li><a href="/net/network_user_devices.lua?sid=' >< res ||
                                          '<li><a href="/system/syslog.lua?sid=' >< res ) ) {
        report = "The URL " + report_vuln_url( port:port, url:url, url_only:TRUE ) + " has no password set.";
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }

  # The GUI is password protected
  url = dir + "/login.lua";

  foreach credential( credentials ) {

    # fallback for later
    fbsleepsecs = 2;

    req = http_get( port:port, item:url );
    res = http_send_recv( port:port, data:req );

    # e.g. FonWLAN 7240 with 73.05.05 firmware
    challenge = eregmatch( pattern:"<br>security:status/challenge = ([a-z0-9]+)", string:res );
    if( isnull( challenge[1] ) ) {
      # e.g. FonWLAN 7240 with 73.05.58 or 73.06.06 firmware
      challenge = eregmatch( pattern:'g_challenge = "([a-z0-9]+)"', string:res );
      if( isnull( challenge[1] ) ) {
        continue;
      }
    } else {
      isOld = TRUE;
    }

    response = create_response( challenge:challenge[1], credential:credential );
    if( isOld ) {
      postdata = "response=" + response;
    } else {
      postdata = "response=" + response + "&page=%2Fhome%2Fhome.lua&username=";
    }

    req = http_post_req( port:port, url:url, data:postdata,
                         accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                         add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded",
                                                 "Upgrade-Insecure-Requests", "1",
                                                 "Referer", report_vuln_url( port:port, url:url, url_only:TRUE ) ) );
    res = http_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 303" && "/home/home.lua?sid=" >< res ) {

      sid = eregmatch( pattern:"/home/home\.lua\?sid=([a-z0-9]+)", string:res );
      if( isnull( sid[1] ) ) continue;

      url = "/home/home.lua?sid=" + sid[1];
      req = http_get( port:port, item:url );
      res = http_send_recv( port:port, data:req );

      if( res =~ "^HTTP/1\.[01] 200" && ( '<img src="/css/default/images/icon_abmelden.gif">' >< res || '<li><a href="/net/network_user_devices.lua?sid=' >< res ||
                                          '<li><a href="/system/syslog.lua?sid=' >< res ) ) {
        report = "It was possible to login at " + report_vuln_url( port:port, url:url, url_only:TRUE ) + " with the password '" + credential + "'.";
        security_message( port:port, data:report );
        exit( 0 );
      }
    } else {
      # counter for sleeps between login tries.
      # The box will lock us out with too many tries in a row.
      # Newer firmware versions are also so kind to give us the info how long we need to wait.
      sleepsecs = eregmatch( pattern:"<br>security:status/login_blocked = ([0-9]+)", string:res );
      if( ! isnull( sleepsecs[1] ) ) {
        sleepsecs = sleepsecs[1];
      } else {
        # fallback if we were not able to get the current wait time above
        fbsleepsecs *= 2;
        sleepsecs = fbsleepsecs;
      }
      sleep( sleepsecs );
    }
  }
}

# e.g. 7490 with 06.60 firmware
url = dir + "/";
req = http_get( port:port, item:url );
res = http_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && '"lua":' >< res && ( '"internet\\/dsl_test.lua"' >< res || '"assis\\/assi_fax_intern.lua"' >< res ||
                                                       '"dect\\/podcast.lua"' >< res || '"wlan\\/wlan_settings.lua"' >< res ) ) {
  report = "The URL " + report_vuln_url( port:port, url:url, url_only:TRUE ) + " has no password set.";
  security_message( port:port, data:report );
  exit( 0 );
} else if( res =~ "^HTTP/1\.[01] 200" && "FRITZ!Box" >< res && "login.init(data);" >< res ) {

  # fallback for later
  fbsleepsecs = 2;

  foreach credential( credentials ) {

    req = http_get( port:port, item:url );
    res = http_send_recv( port:port, data:req );

    challenge = eregmatch( pattern:'"challenge": ?"([a-z0-9]+)",', string:res );
    if( isnull( challenge[1] ) ) continue;

    response = create_response( challenge:challenge[1], credential:credential );
    postdata = "response=" + response + "&lp=&username=";

    req = http_post_req( port:port, url:url, data:postdata,
                         accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                         add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded",
                                                 "Upgrade-Insecure-Requests", "1",
                                                 "Referer", report_vuln_url( port:port, url:url, url_only:TRUE ) ) );
    res = http_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && '"lua":' >< res && ( '"internet\\/dsl_test.lua"' >< res || '"assis\\/assi_fax_intern.lua"' >< res ||
                                                           '"dect\\/podcast.lua"' >< res || '"wlan\\/wlan_settings.lua"' >< res ) ) {
      report = "It was possible to login at " + report_vuln_url( port:port, url:url, url_only:TRUE ) + " with the password '" + credential + "'.";
      security_message( port:port, data:report );
      exit( 0 );
   } else {
      # counter for sleeps between login tries.
      # The box will lock us out with too many tries in a row.
      # Newer firmware versions are also so kind to give us the info how long we need to wait.
      sleepsecs = eregmatch( pattern:'"blockTime": ?([0-9]+),', string:res );
      if( ! isnull( sleepsecs[1] ) ) {
        sleepsecs = sleepsecs[1];
      } else {
        # fallback if we were not able to get the current wait time above
        fbsleepsecs *= 2;
        sleepsecs = fbsleepsecs;
      }
      sleep( sleepsecs );
    }
  }
}

exit( 99 );