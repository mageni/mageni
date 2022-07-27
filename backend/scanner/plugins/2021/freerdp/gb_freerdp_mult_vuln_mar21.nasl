# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113802");
  script_version("2021-03-17T11:33:23+0000");
  script_tag(name:"last_modification", value:"2021-03-18 11:03:57 +0000 (Thu, 18 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-17 11:05:26 +0000 (Wed, 17 Mar 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-4030", "CVE-2020-4031", "CVE-2020-4032", "CVE-2020-4033", "CVE-2020-11095", "CVE-2020-11096", "CVE-2020-11097", "CVE-2020-11098", "CVE-2020-11099");

  script_name("FreeRDP < 2.1.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-4030: Out-of-bounds read in TrioParse 

  - CVE-2020-4031: Use-after-free in gdi_SelectObject

  - CVE-2020-4032: Integer casting vulnerability in update_recv_secondary_order

  - CVE-2020-4033: Out-of-bounds read in RLEDECOMPRESS

  - CVE-2020-11095: Out-of-bounds read related to the static array
  PRIMARY_DRAWING_ORDER_FIELD_BYTES

  - CVE-2020-11096: Out-of-bounds read in update_read_cache_bitmap_v3_order

  - CVE-2020-11097: Out-of-bounds read related to the static array
  PRIMARY_DRAWING_ORDER_FIELD_BYTES

  - CVE-2020-11098: Out-of-bounds read in glyph_cache_put

  - CVE-2020-11099: Out-of-bounds read in license_read_new_or_upgrade_license_packet");

  script_tag(name:"impact", value:"Successful exploitation would allow  an attacker to
  access sensitive information or crash the application.");

  script_tag(name:"affected", value:"FreeRDP through version 2.1.1.");

  script_tag(name:"solution", value:"Update to version 2.1.2 or later.");

  script_xref(name:"URL", value:"http://www.freerdp.com/2020/06/22/2_1_2-released");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-fjr5-97f5-qq98");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-gwcq-hpq2-m74g");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-3898-mc89-x2vc");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-7rhj-856w-82p8");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-563r-pvh7-4fw2");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-mjw7-3mq2-996x");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-c8x2-c3c9-9r3f");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-jr57-f58x-hjmv");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-977w-866x-4v5h");

  exit(0);
}

CPE = "cpe:/a:freerdp_project:freerdp";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.1.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.2", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
