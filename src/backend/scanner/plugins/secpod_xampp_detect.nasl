###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xampp_detect.nasl 8141 2017-12-15 12:43:22Z cfischer $
#
# XAMPP Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-10-16
# According to new format
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900526");
  script_version("$Revision: 8141 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 13:43:22 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_name("XAMPP Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed XAMPP
  version and saves the version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

dir = "/xampp";
version = "unknown";
url = dir + "/index.php";
res = http_get_cache( item:dir + "/index.php", port:port );

if( res =~ "^HTTP/1\.[01] 200" && ( "<title>XAMPP" >< res && "start.php" >< res ) ) {

  installed = TRUE;
  install = dir;
  vers = eregmatch( pattern:"<title>XAMPP (Version )?([0-9.]+)", string:res );
  if( ! isnull ( vers[2] ) ) version = vers[2];
  conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
}

if( ! installed || version == "unknown" ) {

  url = dir + "/start.php";
  res = http_get_cache( item:dir + "/start.php", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && ( "<h1>Welcome to XAMPP" >< res || "and all other friends of XAMPP!<p>" >< res ||
                                      "You successfully installed XAMPP on this system!" >< res ) ) {
    installed = TRUE;
    install = dir;
    vers = eregmatch( pattern:"XAMPP.*Version ([0-9.]+)", string:res );
    if( ! isnull ( vers[1] ) ) version = vers[1];
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( ! installed || version == "unknown" ) {

  # Location for the newer 5.6.x versions
  url = "/dashboard";
  install = url;
  res = http_get_cache( item:url + "/", port:port );

  if( res =~ "^HTTP/1\.[01] 200" && ( "<h1>Welcome to XAMPP" >< res || "You have successfully installed XAMPP on this system!" >< res ) ) {
    installed = TRUE;
    vers = eregmatch( pattern:"<h2>Welcome to XAMPP.* ([0-9.]+)</h2>", string:res );
    if( ! isnull ( vers[1] ) ) version = vers[1];
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( installed ) {

  set_kb_item( name:"www/" + port + "/XAMPP", value:version );
  set_kb_item( name:"xampp/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apachefriends:xampp:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:apachefriends:xampp';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"XAMPP",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );