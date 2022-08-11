# OpenVAS Vulnerability Test
# $Id: kerio_wrf_management_detection.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Kerio WinRoute Firewall HTTP/HTTPS Management Detection
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
# Changes by Tenable :
#  - Improved version extraction
#  - Report layout
#  - Fixed SSL detection
#
# Copyright:
# Copyright (C) 2005 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host is running a firewall application. 

Description :

The remote host appears to be running the Kerio WinRoute Firewall
application.  It is possible to access the HTTP or HTTPS management
interface on the host.";

tag_solution = "If the service is not needed, disable HTTP and/or HTTPS management, 
or filter incoming requests to the ports from untrusted sources.";

if (description) {
 script_oid("1.3.6.1.4.1.25623.1.0.300002");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 name = "Kerio WinRoute Firewall HTTP/HTTPS Management Detection";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Firewalls");

 script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 4080, 4081);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.20225";
SCRIPT_DESC = "Kerio WinRoute Firewall HTTP/HTTPS Management Detection";

port = get_http_port(default:4080);

res = http_get_cache(item: "/", port: port);
if (!res) exit(0);
if ("Kerio WinRoute Firewall" >< res &&
      ( line = egrep(pattern: "Kerio WinRoute Firewall [0-9.]+", string: res)))
{
  # Check and build the version.
  version = ereg_replace(pattern:".*Kerio WinRoute Firewall ([0-9.]+).*", string:line, replace:"\1");
  if (version == line ) version = NULL;

  if ( version != NULL )
  {
    report = string(
    "The Kerio WinRoute Firewall Management Webserver is listening on this port.\n",
    "The version of the application is :\n",version); 
  }
  else report = '';

  if ( version != NULL ){
    set_kb_item(name:"Services/www/" + port + "/kerio_wrf", value:version);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: version, exp:"^([0-9.]+)",base:"cpe:/a:kerio:winroute_firewall:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  }
  security_message(port: port, data: report);

  exit(0);
}
