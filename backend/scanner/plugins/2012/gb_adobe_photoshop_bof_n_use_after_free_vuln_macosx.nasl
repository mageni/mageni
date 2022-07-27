###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_bof_n_use_after_free_vuln_macosx.nasl 11861 2018-10-12 09:29:59Z cfischer $
#
# Adobe Photoshop BOF and Use After Free Vulnerabilities (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802786");
  script_version("$Revision: 11861 $");
  script_cve_id("CVE-2012-2027", "CVE-2012-2028", "CVE-2012-2052", "CVE-2012-0275");
  script_bugtraq_id(53421, 52634, 53464, 55372);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:29:59 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-05-16 12:11:54 +0530 (Wed, 16 May 2012)");
  script_name("Adobe Photoshop BOF and Use After Free Vulnerabilities (Mac OS X)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/48457/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027046");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-11.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code.");
  script_tag(name:"affected", value:"Adobe Photoshop version prior to CS6 on Mac OS X");
  script_tag(name:"insight", value:"The flaws are due to

  - An insufficient input validation while decompressing TIFF images.

  - An input sanitisation error when parsing TIFF images can be exploited
    to cause a heap based buffer overflow via a specially crafted file.");
  script_tag(name:"summary", value:"This host is installed with Adobe Photoshop and is prone to buffer
  overflow and use after free vulnerabilities.");
  script_tag(name:"solution", value:"Apply patch for Adobe Photoshop CS5 and CS5.1, or upgrade to Adobe Photoshop version CS6 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://helpx.adobe.com/photoshop/kb/security-update-photoshop.html");
  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:adobe:photoshop_cs5",
                      "cpe:/a:adobe:photoshop_cs5.1" );

if( ! vers = get_app_version( cpe:cpe_list ) ) exit( 0 );

## Adobe Photoshop CS5 (12.0.5) and CS5.1 (12.1.1)
if( version_is_less( version:vers, test_version:"12.0.5" ) ) {
  installed = "CS5 " + vers;
  fixed = "CS5 12.0.5";
}

if( vers =~ "^12\.1" ) {
  if( version_is_less( version:vers, test_version:"12.1.1" ) ) {
    installed = "CS5.1 " + vers;
    fixed = "CS5.1 12.1.1";
  }
}

if( fixed ) {
  report = report_fixed_ver( installed_version:installed, fixed_version:fixed );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );