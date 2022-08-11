###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aastra_opencom_detect.nasl 10906 2018-08-10 14:50:26Z cfischer $
#
# Aastra OpenCom Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103683");
  script_version("$Revision: 10906 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2013-03-20 16:20:02 +0100 (Wed, 20 Mar 2013)");
  script_name("Aastra OpenCom Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Aastra OpenCom.

  The script sends a connection request to the server and attempts to
  determine the model from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if( ! can_host_asp( port:port ) ) exit( 0 );

foreach url( make_list( "/", "/index.html", "/home.asp?state=0" ) ) {

 buf = http_get_cache( item:url, port:port );

 if("<title>opencom" >!< tolower(buf))continue;

 typ = eregmatch(pattern:"<TITLE>OpenCom ([^<]+)</TITLE>", string:buf, icase:TRUE);

 if(isnull(typ[1])) {
   model = "unknown";
   cpe = 'cpe:/h:aastra_telecom:opencom';
 } else {
   model = typ[1];
   cpe = 'cpe:/h:aastra_telecom:opencom_' + tolower(model);
 }

 register_product(cpe:cpe, location:url, port:port);
 set_kb_item(name:"aastra_opencom/model", value: model);

 log_message(data: build_detection_report(app:"Detected Aastra OpenCom", version:model, install:url, cpe:cpe, concluded: typ[0]),
             port:port);
 exit(0);
}

exit(0);
