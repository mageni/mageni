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

CPE = "cpe:/o:d-link:dir-2150_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170326");
  script_version("2023-03-01T10:09:26+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:09:26 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-28 08:13:15 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: v4.01_Beta Hotfix not detected

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-3210", "CVE-2022-40717", "CVE-2022-40718", "CVE-2022-40719",
                "CVE-2022-40720");

  script_name("D-Link DIR-2150 <= 4.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected");

  script_tag(name:"summary", value:"D-Link DIR-2150 devices are prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-3210: xupnpd ui_upload command injection remote code execution vulnerability

  - CVE-2022-40717: anweb action_handler stack-based buffer overflow remote code execution vulnerability

  - CVE-2022-40718: anweb websocket_data_handler stack-based buffer overflow remote code execution
  vulnerability

  - CVE-2022-40719: xupnpd_generic plugin command injection remote code execution vulnerability

  - CVE-2022-40720: xupnpd Dreambox plugin command injection remote code execution vulnerability");

  script_tag(name:"affected", value:"D-Link DIR-2150 devices through firmware version 4.0.1.");

  script_tag(name:"solution", value:"Update to 4.01_Beta Hotfix or later.");

  script_xref(name:"URL", value:"https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10304");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-1220/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-1221/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-1222/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-1223/");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-22-1224/");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

# nb: some of the versions might contain _Beta or other suffixes, using revcomp to be on the safe side
if ( revcomp( a:version, b:"4.0.1" ) <= 0 ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.01_Beta Hotfix" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
