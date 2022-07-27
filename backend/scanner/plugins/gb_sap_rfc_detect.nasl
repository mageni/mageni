###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sap_rfc_detect.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# SAP RFC Interface Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141120");
  script_version("$Revision: 10899 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-05-30 08:06:33 +0700 (Wed, 30 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SAP RFC Interface Detection");

  script_tag(name:"summary", value:"Detection of SAP RFC Interface.

The RFC (Remote Function Call) interface enables function calls between two SAP systems, or between an SAP system
and an external system.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://archive.sap.com/documents/docs/DOC-60424");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8000);

url = '/sap/bc/soap/rfc';

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("Logon failed" >< res && "sap-system" >< res) {
  set_kb_item(name: "sap_rfc/detected", value: TRUE);
  set_kb_item(name: "sap_rfc/port", value: port);

  report = "SAP RFC Interface is enabled at the following URL:  " +
           report_vuln_url(port: port, url: url, url_only: TRUE);
  log_message(port: port, data: report);
  exit(0);
}

exit(0);
