###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Photoshop Multiple Vulnerabilities.
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

CPE = "cpe:/a:adobe:photoshop_cs5";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902374");
  script_version("2019-05-16T08:02:32+0000");
  script_tag(name:"last_modification", value:"2019-05-16 08:02:32 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2011-06-02 11:54:09 +0200 (Thu, 02 Jun 2011)");
  script_cve_id("CVE-2011-2164");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Photoshop Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025483");
  script_xref(name:"URL", value:"http://www.adobe.com/support/downloads/detail.jsp?ftpID=4973");
  script_xref(name:"URL", value:"http://blogs.adobe.com/jnack/2011/05/photoshop-12-0-4-update-for-cs5-arrives.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to crash the application and to
  cause a Denial of Service.");

  script_tag(name:"affected", value:"Adobe Photoshop CS5 before 12.0.4.");

  script_tag(name:"insight", value:"Multiple flaws are present due to errors in Liquify save mesh, Sharpen,
  Quick Selection, and Orphea Studio File Info.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CS5 12.0.4 or later.");

  script_tag(name:"summary", value:"This host is installed with Adobe Photoshop and is prone to multiple
  vulnerabilities.");

  script_xref(name:"URL", value:"http://www.adobe.com/support/downloads/thankyou.jsp?ftpID=4973&fileID=4688");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"12.0.4" ) ) {
  report = report_fixed_ver( installed_version:"CS5 " + vers, fixed_version:"12.0.4", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
