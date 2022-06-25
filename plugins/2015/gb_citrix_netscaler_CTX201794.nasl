###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_CTX201794.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Citrix NetScaler Service Delivery Appliance Multiple Security Updates (CTX202482)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:citrix:netscaler";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105468");
  script_cve_id("CVE-2015-7996", "CVE-2015-7997", "CVE-2015-7998");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12106 $");

  script_name("Citrix NetScaler Service Delivery Appliance Multiple Security Updates (CTX202482)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX202482");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:
CVE-2015-7996: Vulnerability in Citrix NetScaler Service Delivery Appliance Service VM (SVM) Nitro API could result in browser cache cleartext credential theft.
CVE-2015-7997: Cross-Site Scripting vulnerabilities in Citrix NetScaler Service Delivery Appliance Service VM (SVM) User Interface Nitro API.
CVE-2015-7998: Vulnerability in Citrix NetScaler Service Delivery Appliance Service VM (SVM) administration UI could result in local information disclosure.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to:
Citrix NetScaler ADC and NetScaler Gateway version 10.5 Build 58.11 and later and 10.5.e Build 56.1505.e and later
and 10.1 Build 133.9 and later.");

  script_tag(name:"summary", value:"A number of vulnerabilities have been identified in Citrix NetScaler Service Delivery Appliance (SDX) Service VM (SVM).");

  script_tag(name:"affected", value:"Version 10.5 and 10.5e up to and including 10.5 Build 57.7 and 10.5 Build 54.9009.e
Version 10.1, 10.1e and earlier up to and including 10.1 Build 132.8");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-16 11:03:39 +0100 (Mon, 16 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_citrix_netscaler_version.nasl");
  script_mandatory_keys("citrix_netscaler/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers =  get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );
if( get_kb_item( "citrix_netscaler/enhanced_build" ) ) enhanced = TRUE;

if( enhanced )
{
  if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.55.8006" ) )
  {
    fix = '10.5.e Build 55.8007.e';
    vers = vers + '.e';
  }
}
else
{
  if( version_in_range( version:vers, test_version:'10.5', test_version2:'10.5.55.6' ) )
  {
    fix = '10.5 Build 55.7';
  }

  if( version_in_range( version:vers, test_version:'10.1', test_version2:'10.1.131.6' ) )
  {
    fix = '10.1 Build 131.7';
  }
}

if( fix )
{
  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + fix + '\n';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

