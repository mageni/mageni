###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Acrobat Multiple Vulnerabilities -01 Jan 13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803434");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2012-1530", "CVE-2013-0601", "CVE-2013-0602", "CVE-2013-0603",
                "CVE-2013-0604", "CVE-2013-0605", "CVE-2013-0606", "CVE-2013-0607",
                "CVE-2013-0608", "CVE-2013-0609", "CVE-2013-0610", "CVE-2013-0611",
                "CVE-2013-0612", "CVE-2013-0613", "CVE-2013-0614", "CVE-2013-0615",
                "CVE-2013-0616", "CVE-2013-0617", "CVE-2013-0618", "CVE-2013-0619",
                "CVE-2013-0620", "CVE-2013-0621", "CVE-2013-0622", "CVE-2013-0623",
                "CVE-2013-0624", "CVE-2013-0626", "CVE-2013-0627", "CVE-2013-1376");
  script_bugtraq_id(57264, 57272, 57289, 57282, 57283, 57273, 57263, 57290, 57291,
                    57286, 57284, 57292, 57265, 57287, 57293, 57268, 57274, 57269,
                    57294, 57275, 57276, 57270, 57295, 57277, 57296, 57285, 57297, 65275);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2013-03-12 19:05:12 +0530 (Tue, 12 Mar 2013)");
  script_name("Adobe Acrobat Multiple Vulnerabilities -01 Jan 13 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Adobe Acrobat and is prone to multiple
vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"For more details about the vulnerabilities refer the reference section.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions, execute arbitrary code in the context of the affected
application or cause a denial of service.");
  script_tag(name:"affected", value:"Adobe Acrobat versions 9.x to 9.5.2, 10.x to 10.1.4 and 11.0.0 on Windows");
  script_tag(name:"solution", value:"Upgrade to Adobe Acrobat version 9.5.3 or 10.1.5 or 11.0.1 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51791");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027952");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"9.0", test_version2:"9.5.2" ) ||
    version_in_range( version:vers, test_version:"10.0", test_version2:"10.1.4" )||
    version_is_equal( version:vers, test_version:"11.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.5.3/10.1.5/11.0.1", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );