###############################################################################
# OpenVAS Vulnerability Test
#
# Novell iPrint Client 'printer-url' Multiple BOF Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801951");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-1699", "CVE-2011-1700", "CVE-2011-1701", "CVE-2011-1702",
                "CVE-2011-1703", "CVE-2011-1704", "CVE-2011-1705", "CVE-2011-1706",
                "CVE-2011-1707", "CVE-2011-1708");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Novell iPrint Client 'printer-url' Multiple BOF Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1025606");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-172/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-173/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-174/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-175/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-176/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-177/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-178/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-179/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-180/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-181/");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code under
  the context of the browser.");
  script_tag(name:"affected", value:"Novell iPrint Client version prior to 5.64 on windows.");
  script_tag(name:"insight", value:"The flaws exist within the 'nipplib' component which is used by both the
  ActiveX and Netscape compatible browser plugins. When handling the various
  parameters from the user specified printer-url the process blindly copies
  user supplied data into a fixed-length buffer on the heap.");
  script_tag(name:"solution", value:"Upgrade to Novell iPrint Client 5.64 or later.");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=6_bNby38ERg~");
  script_tag(name:"summary", value:"The host is installed with Novell iPrint Client and is prone to
  multiple buffer overflow vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"5.64" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.64", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
