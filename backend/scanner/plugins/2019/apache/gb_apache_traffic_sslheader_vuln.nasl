# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141998");
  script_version("$Revision: 13651 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 08:17:34 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-14 13:58:24 +0700 (Thu, 14 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-11783");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Traffic Server (ATS) sslheader Plugin vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");

  script_tag(name:"summary", value:"sslheaders plugin extracts information from the client certificate and sets
headers in the request based on the configuration of the plugin.  The plugin doesn't strip the headers from the
request in some scenarios.");

  script_tag(name:"affected", value:"Apache Traffic Server versions 6.x, 7.x and 8.x.");

  script_tag(name:"solution", value:"Update to version 7.1.6, 8.0.2 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2019/q1/132");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "6.0.0", test_version2: "7.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.1.6");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0.0", test_version2: "8.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
