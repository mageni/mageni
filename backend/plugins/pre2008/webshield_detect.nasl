# OpenVAS Vulnerability Test
# $Id: webshield_detect.nasl 9584 2018-04-24 10:34:07Z jschulte $
# Description: WebShield Appliance detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17368");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("WebShield Appliance detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports(443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of WebShield Appliance.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = 443;
if(!get_port_state(port))
  exit(0);

req = http_get(item:"/strings.js", port:port);
res = http_send_recv(data:req, port:port);

if ( "Server: WebShield Appliance" >< res ) {

  #var WEBSHIELD_TITLE="WebShield Appliance v3.0";
  title = egrep(pattern:"WEBSHIELD_TITLE=", string:res);
  if ( ! title )
    exit(0);

  vers = 'unknown';
  version = eregmatch(pattern:'WEBSHIELD_TITLE="WebShield Appliance v(0-9.)+"', string:title, icase:TRUE);

  if(!isnull(version[1])) {
    vers = version[1];
  }

  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:network_associates:webshield:");
  if(!cpe)
    cpe = 'cpe:/a:network_associates:webshield';

  register_product(cpe:cpe, location:"/strings.js", port:port);

  log_message(data: build_detection_report(app:"WebShield Appliance", version:vers, install:"/", cpe:cpe, concluded: version[0]),
              port:port);
}

exit(0);