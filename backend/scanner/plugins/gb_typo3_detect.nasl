###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_detect.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# TYPO3 Detection
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Updated by Shakeel <bshakeel@secpod.com> on 2015-01-19
# According to new script style & to detect version from 'ChangeLog'
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803979");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-12-16 18:17:29 +0530 (Mon, 16 Dec 2013)");
  script_name("TYPO3 Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed path and version
  of TYPO3.

  The script sends HTTP GET requests and try to comfirm the TYPO3 installation
  path and version from the response. If the version check is failing it sends
  HTTP POST request and gets the version by authenticating into TYPO3 backend,
  and sets the results in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("url_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("gvr_apps_auth_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir ( make_list_unique( "/", "/cms", "/typo", "/typo3", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;
  installed = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/";
  res = http_get_cache( item:url, port:port );

  url2 = dir + "/typo3/index.php";
  res2 = http_get_cache( item:url2, port:port );

  url3 = dir + "/typo3_src/ChangeLog";
  req  = http_get( item:url3, port:port );
  res3 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res3 !~  "TYPO3 Release Team" ) {
    url3 = dir + "/ChangeLog";
    res3 = http_get_cache( item:url3 , port:port );
  }

  generator_pattern = '<meta name="generator" content="TYPO3';
  pattern = 'content="TYPO3 ([0-9a-z.]+)';

  if( res3 && res3 =~ "^HTTP/1\.[01] 200" && "TYPO3 Release Team" >< res3 ) {
    ver3 = eregmatch( pattern:"Release of TYPO3 ([0-9a-z.]+)", string:res3 );
    installed = TRUE;
    flag = TRUE;
  } else if( res && res =~ "^HTTP/1\.[01] 200" && generator_pattern >< res || ("typo3conf" >< res && "typo3temp" >< res ) ) {
    ver = eregmatch( pattern:pattern, string:res );
    installed = TRUE;
  } else if( res2 && res2 =~ "^HTTP/1\.[01] 200" && generator_pattern >< res2 || "typo3temp" >< res2 ) {
    ver2 = eregmatch( pattern:pattern, string:res2 );
    installed = TRUE;
  }

  if( ! isnull( ver3[1] ) ) {
    conclUrl = report_vuln_url( port:port, url:url3, url_only:TRUE );
    concl = ver3[0];
    typoVer = ver3[1];
  } else if( ! isnull( ver[1] ) ) {
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    concl = ver[0];
    typoVer = ver[1];
  } else if( ! isnull( ver2[1] ) ) {
    conclUrl = report_vuln_url( port:port, url:url2, url_only:TRUE );
    concl = ver2[0];
    typoVer = ver2[1];
  }
  else
  {
    reqs = make_list("/typo3/sysext/recordlist/composer.json", "/typo3/sysext/sys_note/composer.json",
                     "/typo3/sysext/t3editor/composer.json", "/typo3/sysext/opendocs/composer.json");
    foreach url(reqs)
    {
      url_new = dir + url;
      req  = http_get( item:url_new, port:port );
      res  = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      if(res && res =~ "^HTTP/1\.[01] 200" && "TYPO3 Core Team" >< res){
        installed = TRUE;
      }
      ver4 = eregmatch( pattern:'typo3/cms-core": "([0-9a-z.]+)"', string:res );
      if(ver4[1]){
        break ;
      }
    }
    if(ver4[1])
    {
      flag = TRUE;
      conclUrl = report_vuln_url( port:port, url:url_new, url_only:TRUE );
      concl = ver4[0];
      typoVer = ver4[1];
    }
    else{
      typoVer = 'unknown';
    }
  }

  if( installed ) {

    if( dir == "" ) rootInstalled = TRUE;

    tmp_version = typoVer + " under " + install;
    set_kb_item( name:"www/" + port + "/typo3", value:tmp_version );
    set_kb_item( name:"TYPO3/installed", value:TRUE );
    register_and_report_cpe( app:"TYPO3", ver:typoVer, concluded:concl, base:"cpe:/a:typo3:typo3:", expr:"([0-9a-z.]+)", insloc:install, regPort:port, conclUrl:conclUrl );
  }
  if( ! flag && installed ) {
    res = http_get_cache( item:dir + "/typo3/index.php", port:port );

    if( res && ( "<title>TYPO3 Login" >< res || "<title>TYPO3 CMS Login" >< res ) && res =~ "^HTTP/1\.[01] 200" ) {

      vers = "unknown";
      tver = "";
      tmp_version = "";
      cpe = "";
      host = http_host_name( port:port );
      useragent = http_get_user_agent();

      cookie = get_typo3_login_cookie( cinstall:install, tport:port, chost:host );

      if( cookie ) {
        foreach page( make_list( "/alt_main.php", "/backend.php" ) ) {
          url = dir + "/typo3" + page;
          req = string( "GET ", url, " HTTP/1.1\r\n",
                        "Host: ", host, "\r\n",
                        "User-Agent: ", useragent, "\r\n",
                        "Referer: http://", host, url, "\r\n",
                        "Connection: keep-alive\r\n",
                        "Cookie: ", cookie, "\r\n",
                        "Content-Type: application/x-www-form-urlencoded\r\n\r\n" );
          res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

          tver = eregmatch( pattern:"<title>.*\[TYPO3 ([0-9\.]+)([0-9a-z]+)?\]</title>" , string:res );
          if( tver[1] ) {
            vers = tver[1];
            if( tver[2] )
              vers = vers + tver[2];
            break;
          }
        }
      }

      if( vers == "unknown" ) continue;

      get_typo3_logout( loc:install, lport:port, lhost:host, lcookie:cookie );

      tmp_version = vers + " under " + install;
      set_kb_item( name:"www/" + port + "/typo3", value:tmp_version );
      set_kb_item( name:"TYPO3/installed", value:TRUE );

      if( tver[1] ) {
        if( tver[2] )
          cpe = build_cpe( value:tver[1] + ":" + tver[2], exp:"^([0-9.\:a-z]+)", base:"cpe:/a:typo3:typo3:" );
        if( tver[1] && ! tver[2] )
          cpe = build_cpe( value:tver[1], exp:"^([0-9.]+)", base:"cpe:/a:typo3:typo3:" );
      }

      if( isnull( cpe ) )
        cpe = "cpe:/a:typo3:typo3";

      register_and_report_cpe( app:"TYPO3", ver:vers, cpename:cpe, insloc:install, regPort:port );
    }
  }
}

exit( 0 );
