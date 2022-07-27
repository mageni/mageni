###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_netscaler_CTX139017.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Citrix NetScaler Denial of Service Vulnerability (CTX139017)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105274");
  script_bugtraq_id(62788);
  script_cve_id("CVE-2013-6011");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Citrix NetScaler Denial of Service Vulnerability (CTX139017)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/ctx139017");

  script_tag(name:"impact", value:"A denial of service vulnerability has been identified in Citrix NetScaler Application Delivery Controller (ADC).
This vulnerability, when exploited, could cause the Citrix NetScaler appliance to become temporarily unavailable for normal use.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to 10.0-76.7 or newer.");
  script_tag(name:"summary", value:"The remote Citrix Netscaler is prone to a denial of service
vulnerability.");

  script_tag(name:"affected", value:"Citrix NetScaler 10.0 prior to version 10.0-76.7");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-12 13:12:00 +0200 (Tue, 12 May 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_citrix_netscaler_version.nasl");
  script_mandatory_keys("citrix_netscaler/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( get_kb_item( "citrix_netscaler/enhanced_build" ) ) exit( 0 );
if( ! vers =  get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );

if( vers =~ "^10\.0\." )
{
  if( version_is_less( version:vers, test_version: '10.0.76.7') )
  {
    report = 'Installed version: ' + vers + '\n' +
             'Fixed version:     10.0 build 76.7\n';

    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

