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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170224");
  script_version("2023-01-24T10:12:05+0000");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-11-14 09:47:24 +0000 (Mon, 14 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-27624", "CVE-2022-27625", "CVE-2022-27626", "CVE-2022-3576");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Synology DiskStation Manager (DSM) < 7.1.1-42962-2 Multiple Vulnerabilities (Synology-SA-22:17) - Remote Known Vulnerable Versions Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_synology_dsm_consolidation.nasl");
  script_mandatory_keys("synology/dsm/detected");

  script_tag(name:"summary", value:"Multiple Synology NAS devices running DiskStation Manager (DSM)
  are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist / mitigation was done:

  - CVE-2022-27624: A vulnerability regarding improper restriction of operations within the bounds of
  a memory buffer is found in the packet decryption functionality of Out-of-Band (OOB) Management.
  This allows remote attackers to execute arbitrary commands via unspecified vectors.

  - CVE-2022-27625: A vulnerability regarding improper restriction of operations within the bounds of
  a memory buffer is found in the message processing functionality of Out-of-Band (OOB) Management.
  This allows remote attackers to execute arbitrary commands via unspecified vectors.

  - CVE-2022-27626: A vulnerability regarding concurrent execution using shared resource with
  improper synchronization ('Race Condition') is found in the session processing functionality of
  Out-of-Band (OOB) Management. This allows remote attackers to execute arbitrary commands via
  unspecified vectors.

  - CVE-2022-3576: A vulnerability regarding out-of-bounds read is found in the session processing
  functionality of Out-of-Band (OOB) Management. This allows remote attackers to obtain sensitive
  information via unspecified vectors.");

  script_tag(name:"affected", value:"Synology DS3622xs+, FS3410 and HD6500 with firmware versions
  prior to 7.1.1-42962-2.");

  script_tag(name:"solution", value:"Update to firmware version 7.1.1-42962-2 or later.");

  script_xref(name:"URL", value:"https://www.synology.com/en-global/security/advisory/Synology_SA_22_17");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/o:synology:ds3622xs+_firmware",
                      "cpe:/o:synology:fs3410_firmware",
                      "cpe:/o:synology:hd6500_firmware" );

if ( ! infos = get_app_version_from_list( cpe_list:cpe_list, nofork:TRUE ) )
  exit( 0 );

version = infos["version"];

# nb: The patch level version cannot be obtained so when the fix is on a patch level version,
# there will be 2 VTs with different qod_type.
if ( revcomp( a:version, b:"7.1.1-42962" ) < 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.1.1-42962-2" );
  security_message( port:0, data:report );
  exit( 0 );
}

# nb: This is checked by VT 1.3.6.1.4.1.25623.1.0.170292
if ( version =~ "^7\.1\.1-42962" )
  exit( 0 );

exit( 99 );
