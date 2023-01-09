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

CPE = "cpe:/a:synology:router_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127289");
  script_version("2022-12-27T10:18:20+0000");
  script_tag(name:"last_modification", value:"2022-12-27 10:18:20 +0000 (Tue, 27 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-22 08:49:11 +0000 (Thu, 22 Dec 2022)");
  script_tag(name:"cvss_base", value:"8.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager 1.2.x < 1.2.5-8227-6, 1.3.x < 1.3.1-9346-3 Arbitrary Code Execution Vulnerability (Synology_SA_22:25)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to an arbitrary code
  execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The vulnerability allows remote attackers to execute arbitrary
  commands, conduct denial of service (DoS) attacks or read arbitrary files.");

  script_tag(name:"affected", value:"Synology Router Manager version 1.2.x prior to 1.2.5-8227-6
  and 1.3.x prior to 1.3.1-9346-3.");

  script_tag(name:"solution", value:"Update to firmware version 1.2.5-8227-6, 1.3.1-9346-3 or
  later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_25");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if ((version =~ "^1\.2") && (revcomp(a:version, b:"1.2.5-8227-6") < 0)) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.2.5-8227-6");
  security_message(port:0, data:report);
  exit(0);
}

if ((version =~ "^1\.3") && (revcomp(a:version, b:"1.3.1-9346-3") < 0)) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.3.1-9346-3");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
