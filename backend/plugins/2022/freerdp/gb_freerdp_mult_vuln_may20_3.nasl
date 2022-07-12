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
  script_oid("1.3.6.1.4.1.25623.1.0.127068");
  script_version("2022-07-04T10:18:32+0000");
  script_tag(name:"last_modification", value:"2022-07-04 10:18:32 +0000 (Mon, 04 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-01 12:56:11 +0000 (Fri, 01 Jul 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-09 21:46:00 +0000 (Mon, 09 Nov 2020)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-13396", "CVE-2020-13397", "CVE-2020-13398");

  script_name("FreeRDP < 2.1.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_freerdp_detect_lin.nasl");
  script_mandatory_keys("FreeRDP/Linux/Ver");

  script_tag(name:"summary", value:"FreeRDP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-13396: An out-of-bounds (OOB) read vulnerability has been detected in
  ntlm_read_ChallengeMessage in winpr/libwinpr/sspi/NTLM/ntlm_message.c.

  - CVE-2020-13397: An out-of-bounds (OOB) read vulnerability has been detected in
  security_fips_decrypt in libfreerdp/core/security.c due to an uninitialized value.

  - CVE-2020-13398: An out-of-bounds (OOB) write vulnerability has been detected in
  crypto_rsa_common in libfreerdp/crypto/crypto.c.");

  script_tag(name:"affected", value:"FreeRDP prior to version 2.1.1.");

  script_tag(name:"solution", value:"Update to version 2.1.1 or later.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00080.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00054.html");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/commit/8fb6336a4072abcee8ce5bd6ae91104628c7bb69");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/commit/48361c411e50826cb602c7aab773a8a20e1da6bc");
  script_xref(name:"URL", value:"https://github.com/FreeRDP/FreeRDP/commit/8305349a943c68b1bc8c158f431dc607655aadea");
  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less(version: version, test_version: "2.1.1") ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.1", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
