###############################################################################
# OpenVAS Vulnerability Test
# $Id: firestats_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# FireStats Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100226");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-06-21 16:51:00 +0200 (Sun, 21 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("FireStats Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running FireStats, a web statistics system.");

  script_xref(name:"URL", value:"http://firestats.cc/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default: 80);
if (!can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique( "/firestats", "/stats", cgi_dirs( port:port))) {
 install = dir;
 if (dir == "/") dir = "";

 url = dir + "/tools.php?file_id=reset_password";
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if (buf == NULL) continue;

 if (egrep(pattern: '<title>FireStats</title>', string: buf, icase: TRUE) &&
     egrep(pattern: "FireStats [0-9.]+[-a-zA-Z]*<br/>If you have any problems or questions", string:buf)) {
   vers = "unknown";

   version = eregmatch(string: buf, pattern: "FireStats ([0-9.]+[-a-zA-Z]*)",icase:TRUE);
   if (!isnull(version[1])) {
     vers = version[1];
     concUrl = url;
   } else {
     url = dir + "/firestats.info";
     req = http_get(item:url, port:port);
     buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

     version = eregmatch(string: buf, pattern: "FireStats/(.*)",icase:TRUE);

     if (!isnull(version[1])) {
       vers=version[1];
       concUrl = url;
     }
   }

   set_kb_item(name: "firestats/installed", value: TRUE);

   cpe = build_cpe(value: vers, exp: "^([0-9.]+)[. ]?([a-z0-9]+)?", base: "cpe:/a:firestats:firestats:");
   if (!cpe)
     cpe = 'cpe:/a:firestats:firestats';

   register_product(cpe: cpe, location: install, port: port);

   log_message(data: build_detection_report(app: "FireStats", version: vers, install: install, cpe: cpe,
                                            concluded: version[0], concludedUrl: concUrl),
               port: port);
   exit(0);
 }
}

exit(0);
