###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaltura_community_edition_detect.nasl 11224 2018-09-04 12:57:17Z cfischer $
#
# Kaltura Video Platform Detection
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807499");
  script_version("$Revision: 11224 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-04 14:57:17 +0200 (Tue, 04 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-03-18 12:26:14 +0530 (Fri, 18 Mar 2016)");
  script_name("Kaltura Video Platform Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of Kaltura Video Platform.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique("/", "/Kaltura", "/kvd", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/start/index.php", port:port );

  if( rcvRes =~ "HTTP/1.. 200" && rcvRes =~ "title>Kaltura Video Platf(ro|or)m") {

    version = "unknown";
    edition = "";

    ver = eregmatch(pattern: 'Community Edition (Kaltura Server )?([0-9.-]+)', string: rcvRes);
    if(!isnull(ver[2])) {
      version = ver[2];
      set_kb_item(name: "kaltura/version", value: version);
      set_kb_item(name: "kaltura/community/installed", value: TRUE);
      edition = "Community ";
    }
    else {
      ver = eregmatch(pattern: 'OnPrem.* ([0-9.-]+).</h1>', string: rcvRes);
      if (!isnull(ver[1])) {
        version = ver[1];
        set_kb_item(name: "kaltura/version", value: version);
        set_kb_item(name: "kaltura/onprem/installed", value: TRUE);
        edition = "On-Prem ";
      }
    }

    set_kb_item(name: "kaltura/installed", value: TRUE);

    cpe = build_cpe( value:version, exp:"^([0-9.-]+)", base:"cpe:/a:kaltura:kaltura:" );
    if( ! cpe )
      cpe = "cpe:/a:kaltura:kaltura";

    register_product(cpe: cpe, location: install, port: port);

    log_message( data:build_detection_report( app:"Kaltura " + edition + "Edition",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
    exit(0);
  }
}

exit( 0 );
