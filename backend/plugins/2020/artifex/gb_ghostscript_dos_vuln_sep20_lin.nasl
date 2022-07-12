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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113754");
  script_version("2020-09-09T10:24:17+0000");
  script_tag(name:"last_modification", value:"2020-09-09 10:24:17 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 10:14:44 +0000 (Wed, 09 Sep 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-14373");

  script_name("Ghostscript <= 9.25 DoS Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_ghostscript_detect_lin.nasl");
  script_mandatory_keys("artifex/ghostscript/lin/detected");

  script_tag(name:"summary", value:"Ghostscript is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There exists a use after free in igc_reloc_struct_ptr() of psi/igc.c
  which can cause a denial of service when an attacker supplies a specially crafted PDF file.");

  script_tag(name:"affected", value:"Ghostscript through version 9.25.");

  script_tag(name:"solution", value:"Update to version 9.26 or later.");

  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=702851");
  script_xref(name:"URL", value:"https://git.ghostscript.com/?p=ghostpdl.git;a=commitdiff;h=ece5cbbd9979cd35737b00e68267762d72feb2ea;hp=1ef5f08f2c2e27efa978f0010669ff22355c385f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873239");

  exit(0);
}

CPE = "cpe:/a:artifex:ghostscript";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "9.26" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.26", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
