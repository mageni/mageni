# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108620");
  script_cve_id("CVE-2019-1125");
  script_version("2019-08-26T10:45:39+0000");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-26 10:45:39 +0000 (Mon, 26 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-26 10:24:17 +0000 (Mon, 26 Aug 2019)");
  script_name("Greenbone OS - 'Spectre SWAPGS' gadget vulnerability - August 19");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("gb_greenbone_os_detect.nasl");
  script_mandatory_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"The Linux Kernel in Greenbone OS is prone to an information disclosure vulnerability.");

  script_tag(name:"insight", value:"A Spectre gadget was found in the Linux kernel's implementation of system
  interrupts. An attacker with unprivileged local access could use this information to reveal private data through
  a Spectre like side channel.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Greenbone OS 5.0.8.");

  script_tag(name:"affected", value:"Greenbone OS 5.0.x prior to version 5.0.8.");

  script_xref(name:"URL", value:"https://www.greenbone.net/roadmap-lifecycle/#tab-id-2");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/4329821");
  script_xref(name:"URL", value:"https://www.bitdefender.com/business/swapgs-attack.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

if( version =~ "^5\.0" && version_is_less( version:version, test_version:"5.0.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.8" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
