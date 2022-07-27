###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_traffic_server_mult_vuln_aug18.nasl 12343 2018-11-14 02:59:57Z ckuersteiner $
#
# Apache Traffic Server (ATS) Multiple Vulnerabilities (Aug18)
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

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141411");
  script_version("$Revision: 12343 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-14 03:59:57 +0100 (Wed, 14 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-08-30 11:03:19 +0700 (Thu, 30 Aug 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2018-1318", "CVE-2018-8004", "CVE-2018-8005", "CVE-2018-8040");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) Multiple Vulnerabilities (Aug18)");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");

  script_tag(name:"summary", value:"Apache Traffic Server (ATS) is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Apache Traffic Server (ATS) is prone to multiple vulnerabilities:

  - Adding method ACLs in remap.config can cause a segfault when the user makes a carefully crafted request.
(CVE-2018-1318)

  - Multiple HTTP smuggling and cache poisoning issues when clients making malicious requests. (CVE-2018-8004)

  - When there are multiple ranges in a range request, Apache Traffic Server (ATS) will read the entire object from
cache. This can cause performance problems with large objects in cache. (CVE-2018-8005)

  - Pages that are rendered using the ESI plugin can have access to the cookie header when the plugin is configured
not to allow access. (CVE-2018-8040)");

  script_tag(name:"affected", value:"Apache Traffic Server versions 6.0.0 to 6.2.2 and 7.0.0 to 7.1.3.");

  script_tag(name:"solution", value:"Update to version 6.2.3, 7.1.4 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q3/197");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q3/199");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q3/198");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q3/196");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "6.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "7.0.0", test_version2: "7.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
