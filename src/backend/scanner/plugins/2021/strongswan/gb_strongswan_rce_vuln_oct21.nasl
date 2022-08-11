# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:strongswan:strongswan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146955");
  script_version("2021-10-21T06:59:14+0000");
  script_tag(name:"last_modification", value:"2021-10-21 10:37:20 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-20 11:30:11 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-41991");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("strongSwan 4.2.10 < 5.9.4 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("strongswan/detected");

  script_tag(name:"summary", value:"strongSwan is prone to a remote code execution (RCE)
  vulnerability due to an integer overflow.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The in-memory certificate cache in strongSwan has a remote
  integer overflow upon receiving many requests with different certificates to fill the cache and
  later trigger the replacement of cache entries. The code attempts to select a less-often-used
  cache entry by means of a random number generator, but this is not done correctly. Remote code
  execution might be a slight possibility.");

  script_tag(name:"affected", value:"strongSwan version 4.2.10 through 5.9.3.");

  script_tag(name:"solution", value:"Update to version 5.9.4 or later or apply the provided patch.");

  script_xref(name:"URL", value:"https://www.strongswan.org/blog/2021/10/18/strongswan-vulnerability-(cve-2021-41991).html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.2.10", test_version2: "5.9.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.4", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);