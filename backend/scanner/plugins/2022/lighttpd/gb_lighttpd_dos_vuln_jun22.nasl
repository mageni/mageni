# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127041");
  script_version("2022-06-13T06:21:42+0000");
  script_tag(name:"last_modification", value:"2022-06-14 10:02:24 +0000 (Tue, 14 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-13 08:03:33 +0000 (Mon, 13 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2022-30780");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Lighttpd 1.4.56 - 1.4.58 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("sw_lighttpd_detect.nasl");
  script_mandatory_keys("lighttpd/installed");

  script_tag(name:"summary", value:"Lighttpd is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An unauthenticated attacker can send an HTTP request with
  an URL overflowing the maximum URL length, resulting in a denial of service.");

  script_tag(name:"affected", value:"Lighttpd version 1.4.56 through 1.4.58.");

  script_tag(name:"solution", value:"Update to version 1.4.59 or later.");

  script_xref(name:"URL", value:"https://podalirius.net/en/cves/2022-30780/");
  script_xref(name:"URL", value:"https://github.com/p0dalirius/CVE-2022-30780-lighttpd-denial-of-service");
  script_xref(name:"URL", value:"https://github.com/lighttpd/lighttpd1.4");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.4.56", test_version2: "1.4.58")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.59");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
