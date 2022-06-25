# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/o:greenbone:greenbone_os";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108812");
  script_cve_id("CVE-2020-0543", "CVE-2020-0548", "CVE-2020-0549");
  script_version("2020-07-02T07:51:47+0000");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-02 10:22:40 +0000 (Thu, 02 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-02 07:43:24 +0000 (Thu, 02 Jul 2020)");
  script_name("Greenbone OS - Linux Kernel Multiple Vulnerabilities - June 20");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_dependencies("gb_greenbone_os_consolidation.nasl");
  script_mandatory_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"The Linux Kernel in Greenbone OS is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"insight", value:"The Intel June 2020 microcode update is included in GOS, addressing the 'CROSSTalk', 'CacheOut' and 
  'SGAxe' vulnerabilities of Intel processors.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Greenbone OS 6.0.9 or later.");

  script_tag(name:"affected", value:"Greenbone OS 6.0.x prior to version 6.0.9.");

  script_xref(name:"URL", value:"https://www.greenbone.net/roadmap-lifecycle/");
  script_xref(name:"URL", value:"https://www.vusec.net/projects/crosstalk/");
  script_xref(name:"URL", value:"https://cacheoutattack.com/");
  script_xref(name:"URL", value:"https://sgaxe.com/");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

if( version =~ "^6\.0" && version_is_less( version:version, test_version:"6.0.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.0.9" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
