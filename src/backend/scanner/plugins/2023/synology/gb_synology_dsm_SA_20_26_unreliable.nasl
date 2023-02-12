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
  script_oid("1.3.6.1.4.1.25623.1.0.170287");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-19 13:55:18 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-07 12:07:00 +0000 (Wed, 07 Apr 2021)");

  script_cve_id("CVE-2021-26560", "CVE-2021-26561", "CVE-2021-26562", "CVE-2021-26564",
                "CVE-2021-26565", "CVE-2021-26566", "CVE-2021-26567", "CVE-2021-26569",
                "CVE-2021-27646", "CVE-2021-27647", "CVE-2021-27649", "CVE-2021-29083",
                "CVE-2021-29084", "CVE-2021-29085", "CVE-2021-29086", "CVE-2021-29087",
                "CVE-2021-31439", "CVE-2022-22687");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager 6.2.x < 6.2.3-25426-3 Multiple Vulnerabilities (Synology-SA-20:26) - Unreliable Remote Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2021-26560, CVE-2021-26561, CVE-2021-26562: Multiple vulnerabilities in
  synoagentregisterd allow man-in-the-middle attackers to spoof servers via an HTTP session or to
  execute arbitrary code via syno_finder_site HTTP header.

  - CVE-2021-26564, CVE-2021-26565, CVE-2021-26566: Multiple vulnerabilities in synorelayd allows
  man-in-the-middle attackers to execute arbitrary commands via inbound QuickConnect traffic, spoof
  servers and obtain sensitive information via an HTTP session.

  - CVE-2021-26567: Stack-based buffer overflow vulnerability in frontend/main.c in faad2 before
  2.2.7.1 allow local attackers to execute arbitrary code via filename and pathname options.

  - CVE-2021-27646, CVE-2021-27647: Multiple vulnerabilities in iscsi_snapshot_comm_core allows remote
  attackers to execute arbitrary code via crafted web requests.

  - CVE-2021-27649: Use after free vulnerability in file transfer protocol component allows remote
  attackers to execute arbitrary code via unspecified vectors.

  - CVE-2021-26564: Cleartext transmission of sensitive information vulnerability in synorelayd allows
  man-in-the-middle attackers to spoof servers via an HTTP session.

  - CVE-2021-26565: Cleartext transmission of sensitive information vulnerability in synorelayd allows
  man-in-the-middle attackers to obtain sensitive information via an HTTP session.

  - CVE-2021-29083: Improper neutralization of special elements used in an OS command in
  SYNO.Core.Network.PPPoE allows remote authenticated users to execute arbitrary code via realname
  parameter.

  - CVE-2021-29084, CVE-2021-29085: Improper neutralization of special elements in Security Advisor
  report management and file sharing management components allows remote attackers to read arbitrary
  files via unspecified vectors.

  - CVE-2021-29086: Exposure of sensitive information vulnerability in webapi.

  - CVE-2021-29087: Path Traversal vulnerability in webapi component.

  - CVE-2021-31439: An attacker can leverage the lack of proper validation of the length of
  user-supplied data prior to copying it to a heap-based buffer, while processing the DSI structures
  in Netatalk, to execute code in the context of the current process.

  - CVE-2022-22687: Buffer copy without checking size of input ('Classic Buffer Overflow')
  vulnerability in Authentication functionality allows remote attackers to execute arbitrary code via
  unspecified vectors.");

  script_tag(name:"affected", value:"Synology DiskStation Manager version 6.2.x prior to
  6.2.3-25426-3.");

  script_tag(name:"solution", value:"Update to firmware version 6.2.3-25426-3 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_20_26");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: The patch level version cannot be obtained so when the fix is on a patch level version,
# there will be 2 VTs with different qod_type.
if ( ( version =~ "^6\.2\.3-25426" ) && ( revcomp( a:version, b:"6.2.3-25426-3" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.2.3-25426-3" );
  security_message( port:0, data:report );
  exit( 0 );
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170227
if ( ( version =~ "^6\.2" ) && ( revcomp( a:version, b:"6.2.3-25426" ) < 0 ) )
  exit( 0 );

exit( 99 );
