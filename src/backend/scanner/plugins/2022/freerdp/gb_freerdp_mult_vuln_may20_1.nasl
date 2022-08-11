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

CPE = "cpe:/a:freerdp_project:freerdp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127066");
  script_version("2022-07-04T10:18:32+0000");
  script_tag(name:"last_modification", value:"2022-07-04 10:18:32 +0000 (Mon, 04 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-01 11:49:11 +0000 (Fri, 01 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-30 02:15:00 +0000 (Sun, 30 Aug 2020)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-11521", "CVE-2020-11522", "CVE-2020-11523", "CVE-2020-11524",
                "CVE-2020-11525");

  script_name("FreeRDP < 2.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-11521: libfreerdp/codec/planar.c has an out-of-bounds write.

  - CVE-2020-11522: libfreerdp/gdi/gdi.c has an out-of-bounds write.

  - CVE-2020-11523: libfreerdp/gdi/region.c has an integer overflow.

  - CVE-2020-11524: libfreerdp/codec/interleaved.c has an out-of-bounds write.

  - CVE-2020-11525: libfreerdp/cache/bitmap.c has an out of bounds read.");

  script_tag(name:"affected", value:"FreeRDP prior to version 2.0.0.");

  script_tag(name:"solution", value:"Update to version 2.0.0 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-5cwc-6wc9-255w");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-48wx-7vgj-fffh");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-4qrh-8cp8-4x42");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-cgw8-3mp2-p5qw");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-9755-fphh-gmjg");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive(version: version, test_version_lo: "1.0.0", test_version_up: "2.0.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
