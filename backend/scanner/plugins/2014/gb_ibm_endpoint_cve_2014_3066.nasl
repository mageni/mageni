###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_endpoint_cve_2014_3066.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# IBM Endpoint Manager XML External Entity Injection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105130");
  script_cve_id("CVE-2014-0224");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14185 $");

  script_name("IBM Endpoint Manager XML External Entity Injection");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673961");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673964");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21673967");

  script_tag(name:"impact", value:"This vulnerability could allow an attacker to access files
  on an affected server or cause an affected server to make an arbitrary HTTP GET request.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IBM Endpoint Manager could allow a remote attacker to obtain
  sensitive information, caused by an XML External Entity Injection (XXE) error when processing XML
  data. By sending specially-crafted XML data, an attacker could exploit this vulnerability to access
  files and obtain sensitive information on the server.");

  script_tag(name:"affected", value:"All 9.1 releases of the Console, Root Server, Web Reports and Server API
  earlier than 9.1.1088.0

  All 9.0 releases of the Console, Root Server, Web Reports and Server API earlier than 9.0.853.0

  All 8.2 releases of Web Reports and Server API earlier than 8.2.1445.0");

  script_tag(name:"summary", value:"IBM Endpoint Manager is prone to a XML External Entity Injection");

  script_tag(name:"solution", value:"Update to the latest version.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-12-03 14:44:19 +0100 (Wed, 03 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_require_ports("Services/www", 52311);
  script_mandatory_keys("ibm_endpoint_manager/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version =~ "^9\.1\.[0-9]+" )
{
  cv = split( version, sep:'.', keep:FALSE );
  ck_version = cv[2];

  if( int( ck_version ) < int( 1088 ) )
  {
    VULN = TRUE;
    fixed_version = '9.1.1088.0';
  }
}

else if( version =~ "^9\.0\.[0-9]+" )
{
  cv = split( version, sep:'.', keep:FALSE );
  ck_version = cv[2];

  if( int( ck_version ) < int( 853 ) )
  {
    VULN = TRUE;
    fixed_version = '9.0.853.0';
  }
}

else if( version =~ "^8\.2\.[0-9]+" )
{
  cv = split( version, sep:'.', keep:FALSE );
  ck_version = cv[2];

  if( int( ck_version ) < int( 1445 ) )
  {
    VULN = TRUE;
    fixed_version = '8.2.1445.0';
  }
}


if( VULN )
{
  report = 'Installed version: ' + version + '\nFixed version:     ' + fixed_version + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );