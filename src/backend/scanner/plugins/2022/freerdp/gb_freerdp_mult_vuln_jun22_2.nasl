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
  script_oid("1.3.6.1.4.1.25623.1.0.124221");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-11-30 09:08:12 +0000 (Wed, 30 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-39316", "CVE-2022-39317", "CVE-2022-39318", "CVE-2022-39319",
                "CVE-2022-39320", "CVE-2022-39347", "CVE-2022-41877");

  script_name("FreeRDP < 2.9.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-39316: There is an out-of-bounds read in ZGFX decoder component of FreeRDP. A malicious
  server can trick a FreeRDP based client to read out of bound data and try to decode it likely
  resulting in a crash.

  - CVE-2022-39317: Missing range check for input offset index in ZGFX decoder. A malicious server
  can trick a FreeRDP based client to read out of bound data and try to decode it.

  - CVE-2022-39318: Missing input validation in urbdrc channel. A malicious server can trick
  a FreeRDP based client to crash with division by zero.

  - CVE-2022-39319: Missing input length validation in urbdrc channel. A malicious server can trick
  a FreeRDP based client to read out of bound data and send it back to the server.

  - CVE-2022-39320: Integer addition on too narrow types leads to allocation of a buffer too small
  holding the data written. A malicious server can trick a FreeRDP based client to read out of
  bound data and send it back to the server.

  - CVE-2022-39347: Missing path canonicalization and base path check for drive channel.
  A malicious server can trick a FreeRDP based client to read files outside the shared directory.

  - CVE-2022-41877: Missing input length validation in drive channel. A malicious server can trick
  a FreeRDP based client to read out of bound data and send it back to the server.");

  script_tag(name:"affected", value:"FreeRDP prior to version 2.9.0.");

  script_tag(name:"solution", value:"Update to version 2.9.0 or later.");

  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/commit/e865c24efc40ebc52e75979c94cdd4ee2c1495b0");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-99cm-4gw7-c8jh");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-387j-8j96-7q35");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-mvxm-wfj2-5fvh");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-qfq2-82qr-7f4j");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-c5xq-8v35-pffg");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/security/advisories/GHSA-pmv3-wpw4-pw5h");


  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "2.9.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.0", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
