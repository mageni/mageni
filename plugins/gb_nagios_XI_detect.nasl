###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_XI_detect.nasl 10913 2018-08-10 15:35:20Z cfischer $
#
# Nagios XI Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100752");
  script_version("$Revision: 10913 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:35:20 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Nagios XI Detection");
  script_tag(name:"summary", value:"Detection of installed path and version of
  Nagios XI.

  The script sends HTTP GET requests and try to confirm the Nagios XI
  installation and sets the results in KB.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir( make_list_unique( "/nagiosxi", "/nagios", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/login.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

  if(egrep(pattern: "Set-Cookie: nagiosxi", string: buf, icase: TRUE) &&
    "Nagios Enterprises" >< buf && ("Nagios XI - Login" >< buf || ">Nagios XI<" >< buf))
  {
    vers = string("unknown");

    version = eregmatch(string: buf, pattern: 'footernotice">Nagios XI (20[0-9]{2}[^ ]+)',icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }
    else {
      version =  eregmatch(string: buf, pattern: 'name="version" value="(([0-9.]+)|(20[0-9]{2}[^ ]+))">');
      if (!isnull(version[1]))
        vers = chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/nagiosxi"), value: string(vers," under ",install));

    set_kb_item(name:"nagiosxi/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"([0-9.]+)|(20[0-9]{2}[^ ]+)", base:"cpe:/a:nagios:nagiosxi:");
    if(isnull(cpe))
      cpe = 'cpe:/a:nagios:nagiosxi:';

    register_product(cpe:cpe, location:install,port:port);

    log_message(data: build_detection_report(app:"Nagios XI", version:vers, install:install,
                cpe:cpe, concluded:vers), port:port);

 }
}

exit(0);
