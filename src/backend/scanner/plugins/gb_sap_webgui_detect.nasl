###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_webgui_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# SAP Web GUI Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141116");
  script_version("$Revision: 10908 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-05-25 13:20:49 +0700 (Fri, 25 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SAP Web GUI Detection");

  script_tag(name:"summary", value:"Detection of SAP Web GUI.

SAP Web GUI offers the equivalent functions as a SAP GUI Client over HTTP/S accessible through a browser.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://wiki.scn.sap.com/wiki/display/ATopics/SAP+GUI+Family");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

url = '/sap/bc/gui/sap/its/webgui';

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "<title>Logon( - SAP Web Application Server)?</title>" && 'name="sap-system-login"' >< res) {
  set_kb_item(name: "sap_webgui/installed", value: TRUE);
  set_kb_item(name: "sap_webgui/port", value: port);

  report = "SAP Web GUI is enabled at the following URL:  " + report_vuln_url(port: port, url: url, url_only: TRUE);
  log_message(port: port, data: report);
  exit(0);
}

exit(0);
