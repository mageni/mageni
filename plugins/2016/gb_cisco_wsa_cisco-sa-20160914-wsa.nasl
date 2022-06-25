###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wsa_cisco-sa-20160914-wsa.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco Web Security Appliance HTTP Load Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = 'cpe:/h:cisco:web_security_appliance';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106255");
  script_version("$Revision: 12431 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-16 12:38:55 +0700 (Fri, 16 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2016-6407");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Cisco Web Security Appliance HTTP Load Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");

  script_tag(name:"summary", value:"A vulnerability in HTTP request forwarding with Cisco AsyncOS for
Cisco Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to cause a denial of service
(DoS) condition due to link saturation.");

  script_tag(name:"insight", value:"The vulnerability is due to how HTTP data ranges are downloaded from the
destination server. An attacker could exploit this vulnerability by sending multiple crafted HTTP requests to the
targeted device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to trigger multiple simultaneous
downloads for the same HTTP data. This could cause a DoS condition due to heavy traffic on the connection to the
server.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160914-wsa");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'5.6.0-623',
		'6.0.0-000',
		'7.1.0',
		'7.1.1',
 		'7.1.2',
		'7.1.3',
		'7.1.4',
		'7.5.0-000',
		'7.5.0-825',
		'7.5.1-000',
		'7.5.2-000',
		'7.5.2-HP2-303',
		'7.7.0-000',
		'7.7.0-608',
		'7.7.1-000',
		'7.7.5-835',
		'8.0.0-000',
		'8.0.5',
		'8.0.5 Hot Patch 1',
		'8.0.6',
		'8.0.7',
		'8.0.6-078',
		'8.0.8-MR-113',
		'8.0.7-142',
		'8.0.6-119',
		'8.5.0.000',
		'8.5.0-497',
		'8.5.2-027',
		'8.5.2-024',
		'8.5.1-021',
		'8.5.3-055',
		'8.8.0-000',
		'8.8.0-085',
		'9.0 Base',
		'9.0.0-193',
		'9.1 Base',
		'9.1.0-000',
		'9.1.0-070',
		'9.5 Base',
		'9.5.0-235',
		'9.5.0-284',
		'9.5.0-444' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "None Available" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit(0);
