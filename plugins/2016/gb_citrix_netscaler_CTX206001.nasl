###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_CTX206001.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# Citrix NetScaler Application Delivery Controller and NetScaler Gateway Multiple Security Updates
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105538");
  script_cve_id("CVE-2016-2071", "CVE-2016-2072");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11922 $");

  script_name("Citrix NetScaler Application Delivery Controller and NetScaler Gateway Multiple Security Updates (CTX206001)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX206001");

  script_tag(name:"insight", value:"The following vulnerabilities have been addressed:

  - CVE-2016-2071: Citrix NetScaler Application Delivery Controller and NetScaler Gateway Command Privilege Elevation Vulnerability Through Un-sanitised NS Web GUI Commands.

  - CVE-2016-2071: Citrix NetScaler Application Delivery Controller and NetScaler Gateway Command Privilege Elevation Vulnerability Through Un-sanitised NS Web GUI Commands.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available");

  script_tag(name:"summary", value:"A number of vulnerabilities have been identified in Citrix NetScaler Application Delivery Controller (ADC) and NetScaler Gateway that could allow a malicious, unprivileged user to perform privileged operations or execute commands.");

  script_tag(name:"affected", value:"Version 11.0 earlier than 11.0 Build 64.34. Version 10.5 earlier than 10.5 Build 59.13 and 10.5.e earlier than 10.5.e Build 59.1305.e. All builds of version 10.1 are affected by CVE-2016-2072 only. CVE-2016-2071 does not affect version 10.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-11 17:00:25 +0100 (Thu, 11 Feb 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
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
  if( version_in_range( version:vers, test_version:"10.5", test_version2:"10.5.59.1304" ) )
  {
    fix = '10.5.e Build 59.1305.e';
    vers = vers + '.e';
  }
}
else
{
  if( version_in_range( version:vers, test_version:'10.5', test_version2:'10.5.59.12' ) )
  {
    fix = '10.5 Build 59.13';
  }

  if( version_in_range( version:vers, test_version:'10.1', test_version2:'10.1.133.8' ) )
  {
    fix = '10.1 build 133.9';
  }

  if( version_in_range( version:vers, test_version:'11.0', test_version2:'11.0.64.33' ) )
  {
    fix = '11.0 Build  64.34';
  }
}

if( fix )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

