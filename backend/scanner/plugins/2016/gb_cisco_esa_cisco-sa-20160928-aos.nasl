###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_esa_cisco-sa-20160928-aos.nasl 12318 2018-11-12 10:35:08Z cfischer $
#
# Cisco Email Security Appliance File Transfer Protocol Denial of Service Vulnerability
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

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106293");
  script_cve_id("CVE-2016-6416");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12318 $");

  script_name("Cisco Email Security Appliance File Transfer Protocol Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-aos");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vulnerability is fixed, please see the referenced advisory for more details.");

  script_tag(name:"summary", value:"A vulnerability in the local File Transfer Protocol (FTP) service on the
Cisco AsyncOS for Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to cause a
denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to lack of throttling of FTP connections. An
attacker could exploit this vulnerability by sending a flood of FTP traffic to the local FTP service on the
targeted device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause a DoS condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 11:35:08 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-29 12:29:18 +0700 (Thu, 29 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-aos");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'9.6.0-000',
		'9.6.0-042',
		'9.6.0-051',
		'9.9.6-026',
		'9.7.1-066' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver( installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

