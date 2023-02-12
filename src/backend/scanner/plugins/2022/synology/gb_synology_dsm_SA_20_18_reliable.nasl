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

CPE = "cpe:/a:synology:diskstation_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170240");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-11-21 08:46:21 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-09 14:59:00 +0000 (Mon, 09 Nov 2020)");

  script_cve_id("CVE-2020-27650", "CVE-2020-27652", "CVE-2020-27656", "CVE-2020-27648");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager 6.2.x < 6.2.3-25426-2 Multiple Vulnerabilities (Synology-SA-20:18) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Synology DiskStation Manager (DSM) is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2020-27650: Synology DiskStation Manager does not set the Secure flag for the session cookie
  in an HTTPS session, which makes it easier for remote attackers to capture this cookie by
  intercepting its transmission within an HTTP session.

  - CVE-2020-27652: Algorithm downgrade vulnerability in QuickConnect allows man-in-the-middle
  attackers to spoof servers and obtain sensitive information via unspecified vectors.

  - CVE-2020-27656: Cleartext transmission of sensitive information vulnerability in DDNS allows
  man-in-the-middle attackers to eavesdrop authentication information of DNSExit via unspecified
  vectors.

  - CVE-2020-27648: Improper certificate validation vulnerability in OpenVPN client allows
  man-in-the-middle attackers to spoof servers and obtain sensitive information via a crafted
  certificate.");

  script_tag(name:"affected", value:"Synology DiskStation Manager version 6.2.x prior to
  6.2.3-25426-2.");

  script_tag(name:"solution", value:"Update to firmware version 6.2.3-25426-2 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_20_18");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: The patch level version cannot be obtained so when fix is on a patch level version,
# there will be 2 VTs with different qod_type.
if ( ( version =~ "^6\.2" ) && ( revcomp( a:version, b:"6.2.3-25426" ) < 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.2.3-25426-2" );
  security_message( port:0, data:report );
  exit( 0 );
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170286
if ( version =~ "^6\.2\.3-25426" )
  exit( 0 );

exit( 99 );
