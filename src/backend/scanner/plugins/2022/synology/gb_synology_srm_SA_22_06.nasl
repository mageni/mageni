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
  script_oid("1.3.6.1.4.1.25623.1.0.170259");
  script_version("2022-12-08T10:12:32+0000");
  script_tag(name:"last_modification", value:"2022-12-08 10:12:32 +0000 (Thu, 08 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-05 11:24:16 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2022-0194", "CVE-2022-23121", "CVE-2022-23122", "CVE-2022-23123",
                "CVE-2022-23124", "CVE-2022-23125");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology Router Manager < 1.2.5-8227-5, 1.3.x < 1.3-9193-1 Multiple Vulnerabilities (Synology-SA-22:06)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_srm_consolidation.nasl");
  script_mandatory_keys("synology/srm/detected");

  script_tag(name:"summary", value:"Synology Router Manager (SRM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Upon the latest release of Netatalk 3.1.13, the Netatalk
  development team disclosed multiple fixed vulnerabilities affecting earlier versions of the
  software.");

  script_tag(name:"affected", value:"Synology Router Manager prior to version 1.2.5-8227-5
  and 1.3.x prior to 1.3-9193-1.");

  script_tag(name:"solution", value:"Update to firmware version 1.2.5-8227-5, 1.3-9193-1 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_06");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( revcomp( a:version, b:"1.2.5-8227-5" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.2.5-8227-5" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( revcomp( a:version, b:"1.3" ) >= 0 && revcomp( a:version, b:"1.3-9193-1" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.3-9193-1" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
