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
  script_oid("1.3.6.1.4.1.25623.1.0.170228");
  script_version("2022-11-16T21:32:16+0000");
  script_tag(name:"last_modification", value:"2022-11-16 21:32:16 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-16 10:31:34 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2022-0194", "CVE-2022-23121", "CVE-2022-23122", "CVE-2022-23123",
                "CVE-2022-23124", "CVE-2022-23125");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager < 6.2.4-25556-6, 7.0 < 7.0.1-42218-4, 7.1 < 7.1-42661-1 Multiple Vulnerabilities (Synology-SA-22:06)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Multiple vulnerabilities allow remote attackers to obtain
  sensitive information and possibly execute arbitrary code via a susceptible version of
  Synology DiskStation Manager (DSM).");

  script_tag(name:"affected", value:"Synology DiskStation Manager prior to version
  6.2.4-25556-6, 7.0.x prior to 7.0.1-42218-4 and 7.1.x prior to 7.1-42661-1.");

  script_tag(name:"solution", value:"Update to firmware version 6.2.4-25556-6, 7.0.1-42218-4, 7.1-42661 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_06");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( revcomp( a:version, b:"6.2.4-25556-6" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.2.4-25556-6" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( revcomp( a:version, b:"7.0" ) >= 0 && revcomp( a:version, b:"7.0.1-42218-4" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.0.1-42218-4" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( revcomp( a:version, b:"7.1" ) >= 0 && revcomp( a:version, b:"7.1-42661-1" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.1-42661-1" );
  security_message( port:0, data:report );
  exit( 0 );
}


exit( 99 );
