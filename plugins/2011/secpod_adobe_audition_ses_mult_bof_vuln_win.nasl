###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Audition '.ses' Multiple Buffer Overflow Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:adobe:audition";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902373");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-0614", "CVE-2011-0615");
  script_bugtraq_id(47841, 47838);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Audition '.ses' Multiple Buffer Overflow Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17278/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-10.html");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5012.php");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/Adobe-Audition-malformed-SES-file");

  script_copyright("Copyright (C) 2011 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Audition/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
code or cause a denial of service via crafted data in unspecified fields in
the TRKM chunk in an Audition Session file.");
  script_tag(name:"affected", value:"Adobe Audition version 3.0.1 and earlier on Windows");
  script_tag(name:"insight", value:"The flaw is due to an error when handling '.SES' (session) format
file, which results in memory corruption, application crash or possibly
execute arbitrary code.");
  script_tag(name:"solution", value:"Upgrade to version CS5.5 or higher.");
  script_tag(name:"summary", value:"The host is installed with Adobe Audition and is prone to multiple
buffer overflow vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.adobe.com/products/audition.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"3.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"CS5.5", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );