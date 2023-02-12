# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.170288");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-19 13:55:18 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-10 19:25:00 +0000 (Thu, 10 Feb 2022)");

  script_cve_id("CVE-2021-43925", "CVE-2021-43926", "CVE-2021-43927", "CVE-2021-43929",
                "CVE-2022-22679", "CVE-2022-22680");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager 6.2.x < 6.2.4-25556-3, 7.x < 7.0.1-42218-2 Multiple Vulnerabilities (Synology-SA-22:01) - Unreliable Remote Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to a OS command
  injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2021-43925, CVE-2021-43926: SQL Injection in the Log Management functionality

  - CVE-2021-43927: SQL Injection in the Security Management functionality

  - CVE-2021-43929: SQL Injection in work flow management

  - CVE-2022-22679: SQL Injection in the Security Management functionality

  - CVE-2022-22680: Exposure of sensitive information to an unauthorized actor in Web Server");

  script_tag(name:"affected", value:"Synology DiskStation Manager version 6.2.x prior to
  6.2.4-25556-3 and 7.x prior to 7.0.1-42218-2.");

  script_tag(name:"solution", value:"Update to firmware version 6.2.4-25556-3, 7.0.1-42218-2 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_01");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: The patch level version cannot be obtained so when the fix is on a patch level version,
# there will be 2 VTs with different qod_type.
if ( ( version =~ "^6\.2\.4-25556" ) && ( revcomp( a:version, b:"6.2.4-25556-3" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.2.4-25556-3" );
  security_message( port:0, data:report );
  exit( 0 );
}

if ( ( version =~ "^7\.0\.1-42218" ) && ( revcomp( a:version, b:"7.0.1-42218-2" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.0.1-42218-2" );
  security_message( port:0, data:report );
  exit( 0 );
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170235
if ( ( ( version =~ "^6\.2" ) && ( revcomp( a:version, b:"6.2.4-25556" ) < 0 ) ) ||
     ( ( version =~ "^7\.0" ) && ( revcomp( a:version, b:"7.0.1-42218" ) < 0 ) ) )
  exit( 0 );

exit( 99 );
