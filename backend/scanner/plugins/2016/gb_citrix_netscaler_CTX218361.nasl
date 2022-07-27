###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_CTX218361.nasl 12318 2018-11-12 10:35:08Z cfischer $
#
# Unauthorized Redirect flaw in Citrix NetScaler ADC could result in session hijack
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
  script_oid("1.3.6.1.4.1.25623.1.0.140036");
  script_cve_id("CVE-2016-9028");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 12318 $");

  script_name("Unauthorized Redirect flaw in Citrix NetScaler ADC could result in session hijack (CTX218361)");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX218361");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available, please see the referenced advisory for more details.");

  script_tag(name:"summary", value:"An unauthorized redirect vulnerability has been identified in Citrix NetScaler ADC that could allow a remote attacker to obtain session cookies of a redirected AAA user.");

  script_tag(name:"affected", value:"The vulnerability affects the following versions of Citrix NetScaler ADC:
Version 11.1 earlier than 11.1 Build 47.14
Version 11.0 earlier than 11.0 Build 65.31/65.35F
Version 10.5 earlier than 10.5 Build 61.11
Version 10.1 earlier than 10.1 Build 135.8");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 11:35:08 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-28 12:53:02 +0200 (Fri, 28 Oct 2016)");
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
  exit( 99 );
else
{
  if( version_in_range( version:vers, test_version:'10.5', test_version2:'10.5.61.10' ) )
  {
    fix = '10.5 Build 61.11';
  }

  if( version_in_range( version:vers, test_version:'10.1', test_version2:'10.1.135.7' ) )
  {
    fix = '10.1 build 135.8';
  }

  if( version_in_range( version:vers, test_version:'11.0', test_version2:'11.0.65.30' ) )
  {
    fix = '11.0 Build 65.31';
  }
   if( version_in_range( version:vers, test_version:'11.1', test_version2:'11.1.47.13' ) )
   {
     fix = '11.1 Build 47.14';
   }
}

if( fix )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:fix );

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

