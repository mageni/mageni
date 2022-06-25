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

CPE = "cpe:/a:squid-cache:squid";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142632");
  script_version("2019-07-19T08:46:01+0000");
  script_tag(name:"last_modification", value:"2019-07-19 08:46:01 +0000 (Fri, 19 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-19 08:04:35 +0000 (Fri, 19 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-12525");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Proxy Cache Security Update Advisory SQUID-2018:3");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_tag(name:"summary", value:"Squid is prone to a denial of service vulnerability due to incorrect buffer
  management when processing HTTP Digest Authentication credentials.");

  script_tag(name:"insight", value:"Due to incorrect input validation the HTTP Request header parser for Digest
  authentication may access memory outside the allocated memory buffer.

  On systems with memory access protections this can result in the Squid process being terminated unexpectedly.
  Resulting in a denial of service for all clients using the proxy.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Squid versions 3.3.9 - 3.5.28 and 4.x - 4.7.");

  script_tag(name:"solution", value:"Update to version 4.8 or later.");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2019_3.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "3.3.9", test_version2: "3.5.28") ||
    version_in_range(version: version, test_version: "4.0", test_version2: "4.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.8");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
