###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_photoshop_insecure_lib_load_vuln.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Photoshop Insecure Library Loading Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901147");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3127");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Photoshop Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41060");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2170");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2010/08/cve-2010-xn-loadlibrarygetprocaddress.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_mandatory_keys("Adobe/Photoshop/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
arbitrary code and conduct DLL hijacking attacks.");
  script_tag(name:"affected", value:"Adobe Photoshop CS2 through CS5");
  script_tag(name:"insight", value:"The flaw is caused by application insecurely loading certain
libraries from the current working directory, which could allow attackers to
execute arbitrary code by tricking a user into opening a file from a network share.");
  script_tag(name:"solution", value:"Apply Adobe Photoshop 12.0.3 update for Adobe Photoshop CS5.");
  script_tag(name:"summary", value:"This host is installed with Adobe Photoshop and is prone to
Insecure Library Loading vulnerability.");

  script_xref(name:"URL", value:"http://www.adobe.com/downloads/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:adobe:photoshop_cs2",
                      "cpe:/a:adobe:photoshop_cs3",
                      "cpe:/a:adobe:photoshop_cs4",
                      "cpe:/a:adobe:photoshop_cs5" );

if( ! vers = get_app_version( cpe:cpe_list ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"12.0.3" ) ) {
  report = report_fixed_ver( installed_version:"CS1-5 " + vers, fixed_version:"CS5 12.0.3" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );