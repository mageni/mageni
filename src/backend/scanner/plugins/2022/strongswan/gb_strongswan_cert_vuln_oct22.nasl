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
  script_oid("1.3.6.1.4.1.25623.1.0.148837");
  script_version("2022-11-02T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-11-02 10:12:00 +0000 (Wed, 02 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-01 13:48:43 +0000 (Tue, 01 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2022-40617");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("strongSwan 4.x < 5.9.8 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_strongswan_ssh_login_detect.nasl");
  script_mandatory_keys("strongswan/detected");

  script_tag(name:"summary", value:"strongSwan is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"strongSwan allows remote attackers to cause a denial of service
  in the revocation plugin by sending a crafted end-entity (and intermediate CA) certificate that
  contains a CRL/OCSP URL that points to a server (under the attacker's control) that doesn't
  properly respond but (for example) just does nothing after the initial TCP handshake, or sends an
  excessive amount of application data.");

  script_tag(name:"affected", value:"strongSwan version 4.x through 5.9.7.");

  script_tag(name:"solution", value:"Update to version 5.9.8 or later or apply the provided patch.");

  script_xref(name:"URL", value:"https://www.strongswan.org/blog/2022/10/03/strongswan-vulnerability-(cve-2022-40617).html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "5.9.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.9.8", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
