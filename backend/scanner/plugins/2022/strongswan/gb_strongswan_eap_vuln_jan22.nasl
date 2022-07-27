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

CPE = "cpe:/a:strongswan:strongswan";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147551");
  script_version("2022-02-01T02:51:09+0000");
  script_tag(name:"last_modification", value:"2022-02-01 11:05:08 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 02:45:57 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2021-45079");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("strongSwan 4.1.2 < 5.9.5 Early EAP-Success Messages Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("strongswan/detected");

  script_tag(name:"summary", value:"strongSwan is prone to an incorrect handling of early
  EAP-Success messages vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A malicious responder can send an EAP-Success message too early
  without actually authenticating the client and (in the case of EAP methods with mutual
  authentication and EAP-only authentication for IKEv2) even without server authentication.");

  script_tag(name:"impact", value:"The vulnerability may allow to bypass the client and in some
  scenarios even the server authentication, or could lead to a denial-of-service attack.");

  script_tag(name:"affected", value:"strongSwan version 4.1.2 through 5.9.4.");

  script_tag(name:"solution", value:"Update to version 5.9.5 or later or apply the provided patch.");

  script_xref(name:"URL", value:"https://www.strongswan.org/blog/2022/01/24/strongswan-vulnerability-(cve-2021-45079).html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.1.2", test_version2: "5.9.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.5", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
