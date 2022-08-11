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
  script_oid("1.3.6.1.4.1.25623.1.0.112809");
  script_version("2020-08-18T12:31:44+0000");
  script_tag(name:"last_modification", value:"2020-08-19 10:25:31 +0000 (Wed, 19 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-17 10:17:40 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-16287", "CVE-2020-16288", "CVE-2020-16289", "CVE-2020-16290",
  "CVE-2020-16291", "CVE-2020-16292", "CVE-2020-16293", "CVE-2020-16294", "CVE-2020-16295",
  "CVE-2020-16296", "CVE-2020-16297", "CVE-2020-16298", "CVE-2020-16299", "CVE-2020-16300",
  "CVE-2020-16301", "CVE-2020-16302", "CVE-2020-16303", "CVE-2020-16304", "CVE-2020-16305",
  "CVE-2020-16306", "CVE-2020-16307", "CVE-2020-16308", "CVE-2020-16309", "CVE-2020-16310",
  "CVE-2020-17538");

  script_name("Ghostscript < 9.51 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ghostscript_detect_lin.nasl");
  script_mandatory_keys("artifex/ghostscript/lin/detected");

  script_tag(name:"summary", value:"Ghostscript is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Buffer overflow

  - Null-pointer dereference

  - Use-after-free

  - Division by zero");

  script_tag(name:"impact", value:"Successful exploitation would allow a remote attacker
  to cause a denial of service or escalate privileges.");

  script_tag(name:"affected", value:"Ghostscript before version 9.51.");

  script_tag(name:"solution", value:"Update to version 9.51 or later.");

  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701785");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701791");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701788");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701786");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701787");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701793");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701795");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701794");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701796");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701792");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701800");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701799");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701801");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701807");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701808");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701815");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701818");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701816");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701819");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701821");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701822");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701829");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701827");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701828");
  script_xref(name:"URL", value:"https://bugs.ghostscript.com/show_bug.cgi?id=701792");

  exit(0);
}

CPE = "cpe:/a:artifex:ghostscript";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "9.51" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.51", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
