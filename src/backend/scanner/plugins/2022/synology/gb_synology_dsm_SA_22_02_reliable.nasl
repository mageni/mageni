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
  script_oid("1.3.6.1.4.1.25623.1.0.170234");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-11-18 13:52:42 +0000 (Fri, 18 Nov 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 15:47:00 +0000 (Wed, 23 Feb 2022)");

  script_cve_id("CVE-2021-44142");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager 6.2.x < 6.2.4-25556-4 Samba Vulnerability (Synology-SA-22:02) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to an arbitrary code
  execution vulnerability in Samba.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Samba versions prior to 4.13.17, 4.14.12 and 4.15.5 with vfs_fruit
  configured allow out-of-bounds heap read and write via specially crafted extended file attributes.");

  script_tag(name:"impact", value:"A remote attacker with write access to extended file attributes can
  execute arbitrary code with the privileges of smbd, typically root.");

  script_tag(name:"affected", value:"Synology DiskStation Manager version 6.2.x prior to
  6.2.4-25556-4.");

  script_tag(name:"solution", value:"Update to firmware version 6.2.4-25556-4 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_02");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: The patch level version cannot be obtained so when the fix is on a patch level version,
# there will be 2 VTs with different qod_type.
if ( ( version =~ "^6\.2" ) && ( revcomp( a:version, b:"6.2.4-25556" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.2.4-25556-4" );
  security_message( port:0, data:report );
  exit( 0 );
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170289
if ( version =~ "^6\.2\.4-25556" )
  exit( 0 );

exit( 99 );
