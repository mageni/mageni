###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat Unspecified vulnerability
#
# Authors:
# Nikta MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800959");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-22 15:34:45 +0200 (Thu, 22 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3461");
  script_bugtraq_id(36638);
  script_name("Adobe Acrobat Unspecified vulnerability");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-15.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code
  on the affected system via malicious files.");
  script_tag(name:"affected", value:"Adobe Acrobat version 9.x before 9.2 on Windows.");
  script_tag(name:"insight", value:"An unspecified error in Adobe Acrobat can be exploited to bypass intended
  file-extension restrictions via unknown vectors.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version 9.2");
  script_tag(name:"summary", value:"This host has Adobe Acrobat installed which is prone to unspecified
  vulnerability.");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"9.0", test_version2:"9.1.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.2", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );