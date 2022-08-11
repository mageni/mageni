###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wsa_cisco-sa-20161026-esawsa3.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco Web Security Appliance JAR Advanced Malware Protection DoS Vulnerability
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

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140022");
  script_cve_id("CVE-2016-6360");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12149 $");

  script_name("Cisco Web Security Appliance JAR Advanced Malware Protection DoS Vulnerability ");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-esawsa3");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in Advanced Malware Protection (AMP) for Cisco Email Security Appliances (ESA) and
  Web Security Appliances (WSA) could allow an unauthenticated, remote attacker to cause a partial
  denial of service (DoS) condition due to the AMP process unexpectedly restarting.

  The vulnerability is due to improper validation of a Java Archive (JAR) file scanned when AMP is
  configured. An attacker could exploit this vulnerability by crafting a JAR file, and attaching
  this JAR file to an email that is then sent through the affected device. An exploit could allow
  the attacker to cause the Cisco ESA and WSA AMP process to unexpectedly restart due to the
  malformed JAR file.

  Cisco has released software updates that address this vulnerability. Workarounds that address this
  vulnerability are not available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-27 13:54:15 +0200 (Thu, 27 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'8.8.0-085',
		'9.0',
		'9.0.0-193',
		'9.1.0',
		'9.1.0-000',
		'9.1.0-070',
		'9.5.0',
		'9.5.0-235',
		'9.5.0-284',
		'9.5.0-444' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

