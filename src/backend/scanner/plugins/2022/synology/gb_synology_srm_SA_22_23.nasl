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
  script_oid("1.3.6.1.4.1.25623.1.0.170272");
  script_version("2022-12-19T13:49:41+0000");
  script_tag(name:"last_modification", value:"2022-12-19 13:49:41 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-14 11:22:34 +0000 (Wed, 14 Dec 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Synology Router Manager 1.2.x, 1.3.x Multiple Vulnerabilities (Synology-SA-22:23)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"During Pwn2Own Toronto 2022, multiple teams exposed multiple
  command injection vulnerabilities in the WAN and LAN interface of Synology RT6600ax. Other
  Synology router devices might be affected.");

  script_tag(name:"affected", value:"Synology Router Manager versions 1.2.x and 1.3.x.");

  script_tag(name:"solution", value:"No known solution is available as of 14th December, 2022.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_23");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( version =~ "^1\.[23]" ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
