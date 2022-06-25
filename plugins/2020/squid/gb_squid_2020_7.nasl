# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.144212");
  script_version("2020-07-03T06:04:23+0000");
  script_tag(name:"last_modification", value:"2020-07-03 10:14:24 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-03 05:56:38 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2020-15049");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Proxy Cache Security Update Advisory SQUID-2020:7");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_tag(name:"summary", value:"Squid is prone to a cache poisoning vulnerability.");

  script_tag(name:"insight", value:"Due to incorrect input validation Squid is vulnerable to a Request Smuggling
  and Poisoning attack against the HTTP cache.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Squid versions 2.0 - 2.STABLE9, 3.0 - 3.5.28, 4.0 - 4.11 and 5.0.1 - 5.0.2.");

  script_tag(name:"solution", value:"Update to version 4.12, 5.0.3 or later.");

  script_xref(name:"URL", value:"https://github.com/squid-cache/squid/security/advisories/GHSA-qf3v-rc95-96j5");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "2\." ||
    version_in_range(version: version, test_version: "3.0", test_version2: "3.5.28") ||
    version_in_range(version: version, test_version: "4.0", test_version2: "4.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.12");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "5.0.1", test_version2: "5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
