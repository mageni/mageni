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

CPE = "cpe:/o:d-link:dir-878_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170324");
  script_version("2023-03-01T10:09:26+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:09:26 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-27 17:53:21 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: 1.30B08 Hotfix_04 not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-48107", "CVE-2022-48108");

  script_name("D-Link DIR-878 <= 1.30B08 Multiple Command Injection Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-878 devices are prone to multiple command injection
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-48107: command injection vulnerability via the component /SetNetworkSettings/IPAddress.

  - CVE-2022-48108: command injection vulnerability via the component
  /SetNetworkSettings/SubnetMask.");

  script_tag(name:"affected", value:"D-Link DIR-878 devices through firmware version 1.30B08.");

  script_tag(name:"solution", value:"Update to firmware version 1.30B08 Hotfix_04 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-w49p-h6v2-88hr");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/cmd%20inject%20in%20IPAddress");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-4g2v-j3c9-cqx4");
  script_xref(name:"URL", value:"https://github.com/migraine-sudo/D_Link_Vuln/tree/main/cmd%20inject%20in%20Netmask");
  script_xref(name:"URL", value:"https://support.dlink.com/resource/SECURITY_ADVISEMENTS/DIR-878/REVA/DIR-878_REVA_RELEASE_NOTES_v1.30B08_HOTFIX_4b.pdf");
  script_xref(name:"URL", value:"https://support.dlink.com/productinfo.aspx?m=DIR-878");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( revcomp( a:version, b:"1.30B08" ) <= 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.30B08 Hotfix_04" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

