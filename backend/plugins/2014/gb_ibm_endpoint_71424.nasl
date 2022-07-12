###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_endpoint_71424.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# IBM Tivoli Endpoint Manager Mobile Device Management Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105132");
  script_bugtraq_id(71424);
  script_cve_id("CVE-2014-6140");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12095 $");

  script_name("IBM Tivoli Endpoint Manager Mobile Device Management Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71424");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21691701");

  script_tag(name:"impact", value:"An attacker could use this vulnerability to steal the victim's cookie-based
authentication credentials and execute arbitrary code.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"BM Tivoli Endpoint Manager Mobile Device Management (MDM) is vulnerable
to cross-site scripting, caused by improper validation of user-supplied input. A remote attacker could exploit
this vulnerability using a specially-crafted URL to execute script in a victim's web browser within the security
context of the hosting web site, after the URL is clicked.");

  script_tag(name:"solution", value:"Upgrade to version 9.0.60100");
  script_tag(name:"summary", value:"IBM Tivoli Endpoint Manager Mobile Device Management is prone to a cross-
site scripting vulnerability because it fails to sanitize user-supplied input.");

  script_tag(name:"affected", value:"Versions prior to IBM Tivoli Endpoint Manager Mobile Device Management 9.0.60100 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-03 16:30:20 +0100 (Wed, 03 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_endpoint_manager_mdm_installed.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ibm_endpoint_manager/MDM");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

include("version_func.inc");

if( ! get_kb_item("ibm_endpoint_manager/MDM") ) exit( 0 );

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version =  get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version !~ "^9\.0\.[0-9]+" ) exit( 0 );

fixed_version = '9.0.60100';

cv = split( version, sep:'.', keep:FALSE );

ck_version = cv[2];

if( int( ck_version ) < int( 60100 ) )
{
    report = 'Installed version: ' + version + '\nFixed version: ' + fixed_version + '\n' ;
    security_message( port:port, data:report );
    exit( 0 );
}

exit( 99 );
