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

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127290");
  script_version("2023-01-03T10:12:12+0000");
  script_tag(name:"last_modification", value:"2023-01-03 10:12:12 +0000 (Tue, 03 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-12-29 08:46:21 +0000 (Thu, 29 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-12075", "CVE-2018-8916");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager 5.2.x, 6.x < 6.2-23739 Multiple Vulnerabilities (Synology_SA_18:24)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-12075: Command injection in EZ-Internet module allows remote authenticated users to
  execute arbitrary commands via the username parameter.

  - CVE-2018-8916: Unverified password change in Change Password allows remote authenticated users
  to reset password without verification.");

  script_tag(name:"affected", value:"Synology DiskStation Manager version 5.2.x and 6.x prior to
  version 6.2-23739.");

  script_tag(name:"solution", value:"Update to firmware version 6.2-23739 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_18_24");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_greater_equal(version: version, test_version: "5.2") &&
    revcomp(a: version, b: "6.2-23739") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2-23739");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
