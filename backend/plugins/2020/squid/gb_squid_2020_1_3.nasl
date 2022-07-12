# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.143454");
  script_version("2020-02-05T06:02:39+0000");
  script_tag(name:"last_modification", value:"2020-02-05 06:02:39 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-05 05:54:49 +0000 (Wed, 05 Feb 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-12528", "CVE-2020-8449", "CVE-2020-8450", "CVE-2020-8517");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Squid Proxy Cache Multiple Security Update Advisories SQUID-2020:1, SQUID-2020:2, SQUID-2020:3");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_squid_detect.nasl");
  script_mandatory_keys("squid_proxy_server/installed");

  script_tag(name:"summary", value:"Squid is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Squid is prone to multiple vulnerabilities:

  - Information Disclosure issue in FTP Gateway (CVE-2019-12528)

  - Improper Input Validation issues in HTTP Request processing (CVE-2020-8449, CVE-2020-8450)

  - Buffer Overflow issue in ext_lm_group_acl helper (CVE-2020-8517)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Squid versions 2.x, 3.x - 3.5.28 and 4.x - 4.9.");

  script_tag(name:"solution", value:"Update to version 4.10 or later.");

  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2020_1.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2020_2.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2020_3.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^2\." ||
    version_in_range(version: version, test_version: "3.0", test_version2: "3.5.28") ||
    version_in_range(version: version, test_version: "4.0", test_version2: "4.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.10");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
