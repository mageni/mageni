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

CPE = "cpe:/o:d-link:dir-882_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170327");
  script_version("2023-03-03T10:59:40+0000");
  script_tag(name:"last_modification", value:"2023-03-03 10:59:40 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-01 11:43:02 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: v1.30.B06 Hotfix not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-41140", "CVE-2022-46560", "CVE-2022-46561", "CVE-2022-46562",
                "CVE-2022-46563", "CVE-2022-46566", "CVE-2022-46568", "CVE-2022-46569",
                "CVE-2022-46570");

  script_name("D-Link DIR-882 Rev. A <= 1.30B06 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-882 Rev. A devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-41140: The specific flaw exists within the lighttpd service, which listens on TCP port 80
  by default. The issue results from the lack of proper validation of the length of user-supplied data
  prior to copying it to a fixed-length stack-based buffer. An attacker can leverage this
  vulnerability to execute code in the context of root.

  - CVE-2022-46560: Stack overflow via the Password parameter in the SetWan2Settings module.

  - CVE-2022-46561: Stack overflow via the Password parameter in the SetWanSettings module.

  - CVE-2022-46562: Stack overflow via the PSK parameter in the SetQuickVPNSettings module.

  - CVE-2022-46563: Stack overflow via the Password parameter in the SetDynamicDNSSettings module.

  - CVE-2022-46566: Stack overflow via the Password parameter in the SetQuickVPNSettings module.

  - CVE-2022-46568: Stack overflow via the AccountPassword parameter in the SetSysEmailSettings
  module.

  - CVE-2022-46569: Stack overflow via the Key parameter in the SetWLanRadioSecurity module.

  - CVE-2022-46570: Stack overflow via the Password parameter in the SetWan3Settings module.");

  script_tag(name:"affected", value:"D-Link DIR-882 Rev. A devices through firmware version
  1.30B06.");

  script_tag(name:"solution", value:"Update to 1.30B06 Hotfix B03 or later.");

  script_xref(name:"URL", value:"https://support.dlink.com/resource/PRODUCTS/DIR-882/REVA/DIR-882%20_REVA_RELEASE_NOTES_v1.30.B06_HOTFIX_B03.pdf");
  script_xref(name:"URL", value:"https://support.dlink.com/ProductInfo.aspx?m=DIR-882-US");
  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10291");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-1290/");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-m8ph-fr33-7cmg");
  script_xref(name:"URL", value:"https://hackmd.io/@0dayResearch/rkXr4BQPi");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-6m47-c6q4-33vq");
  script_xref(name:"URL", value:"https://hackmd.io/@0dayResearch/ry55QVQvj");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-wxrm-98h4-c857");
  script_xref(name:"URL", value:"https://hackmd.io/@0dayResearch/B1C9jeXDi");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-59gg-pj3q-72g8");
  script_xref(name:"URL", value:"https://hackmd.io/@0dayResearch/HkDzZLCUo");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-xf9q-jgmw-h653");
  script_xref(name:"URL", value:"https://hackmd.io/@0dayResearch/SyhDme7wo");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-4j8f-fjpj-x22v");
  script_xref(name:"URL", value:"https://hackmd.io/@0dayResearch/B1SZP0aIo");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-h2f3-jpg6-w3c6");
  script_xref(name:"URL", value:"https://hackmd.io/@0dayResearch/r1R6sWRUs");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-7c4m-cp34-4f9r");
  script_xref(name:"URL", value:"https://hackmd.io/@0dayResearch/r1zsTSmDs");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

hw_version = get_kb_item( "d-link/dir/hw_version" );
if ( ! hw_version )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( ( hw_version =~ "A" ) && ( revcomp( a:version, b:"1.30B06" ) <= 0 ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.30B06 Hotfix B03", extra:"Hardware revision: " + hw_version );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
