###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_op5_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# OP5 Monitor Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

if (description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.103379");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-09 10:33:57 +0100 (Mon, 09 Jan 2012)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OP5 Monitor Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Detection of op5 Monitor

The script sends a connection request to the server and attempts to detect the presence of op5 Monitor and to
extract its version");

  script_xref(name:"URL", value:"https://www.op5.com/");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default: 443);

buf = http_get_cache(item: "/", port: port);

if (egrep(pattern: "Welcome to op5 portal", string: buf, icase: TRUE))
{
   version = "unknown";
   vers = eregmatch(string: buf, pattern: 'Version: *([0-9.]+) *\\| *<a +href=".*/monitor"');

   if ( !isnull(vers[1]) ) {
     version = vers[1];
     set_kb_item(name: "op5/version", value: version);
   }

   set_kb_item(name: "OP5/installed", value: TRUE);

   cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:op5:monitor:");
   if (!cpe)
     cpe = 'cpe:/a:op5:monitor';

   register_product(cpe:cpe, location:"/", port:port);

   log_message(data: build_detection_report(app:"OP5 Monitor", version: version, install: "/", cpe: cpe,
                                            concluded: vers[0]),
               port: port);
   exit(0);
}

exit(0);
