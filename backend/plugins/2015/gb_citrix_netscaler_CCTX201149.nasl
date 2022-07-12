###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_CCTX201149.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Citrix NetScaler Arbitrary Command Injection (CTX201149)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105309");
  script_cve_id("CVE-2015-5080");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Citrix NetScaler Arbitrary Command Injection (CTX201149)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX201149");

  script_tag(name:"impact", value:"A vulnerability has been identified in Citrix NetScaler Application Delivery Controller (ADC) and Citrix NetScaler Gateway Management Interface that could
allow an authenticated malicious user to execute shell commands on the appliance.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to
Citrix NetScaler ADC and NetScaler Gateway 10.5 Build 56.15 or later.
Citrix NetScaler ADC and NetScaler Gateway 10.1 Build 132.8 or later.
Citrix NetScaler 10.5.e Build 56.1505.e or later.");

  script_tag(name:"summary", value:"Vulnerability in Citrix NetScaler Application Deliver Controller and NetScaler Gateway Management Interface Could Result in Arbitrary Command Injection");

  script_tag(name:"affected", value:"Citrix NetScaler
Version 10.5 earlier than 10.5 Build 56.15
Version 10.5.e  earlier than Build 56.1505.e
Version 10.1 earlier than 10.1.132.8");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-07-01 13:34:32 +0200 (Wed, 01 Jul 2015)");
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
  if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.56.1504" ) )
  {
    fix = '10.5 build 56.1504.e';
    vers = vers + '.e';
  }
}
else
{
  if( version_in_range( version:vers, test_version:'10.5', test_version2:'10.5.56.14' ) )
  {
    fix = '10.5 build 56.15';
  }

  if( version_in_range( version:vers, test_version:'10.1', test_version2:'10.1.132.7' ) )
  {
    fix = '10.1 build 132.8';
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

