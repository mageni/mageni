###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_asa_CSCut14209.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco Adaptive Security Appliance XML Parser Denial of Service Vulnerability
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

CPE = "cpe:/a:cisco:asa";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106079");
  script_cve_id("CVE-2016-1385");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_version("$Revision: 12051 $");

  script_name("Cisco Adaptive Security Appliance XML Parser Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160517-asa-xml");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in XML parser code of Cisco Adaptive Security Appliance
Software could allow an authenticated, remote attacker to cause system instability or a reload of the
affected system.

The vulnerability is due to insufficient hardening of the XML parser configuration. An attacker could exploit
this vulnerability in multiple ways by utilizing a malicious file. An attacker with administrative privileges
could exploit this by uploading a malicious XML file on the system and trigger the XML code to parse the
malicious file. Additionally, an attacker with Clienteles SSL VPN access could exploit this vulnerability
by sending a crafted XML file. An exploit would allow the attacker to crash the XML parser process, which
could cause system instability, memory exhaustion, and in some cases lead to a reload of the affected system.

Cisco has released software updates that address this vulnerability. Workarounds that address this vulnerability
are not available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-19 09:47:55 +0700 (Thu, 19 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_asa_version.nasl", "gb_cisco_asa_version_snmp.nasl");
  script_mandatory_keys("cisco_asa/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork: TRUE ) ) exit( 0 );
check_vers = ereg_replace(string:version, pattern:"\(([0-9.]+)\)", replace:".\1");

affected = make_list(
		'8.4.1',
		'8.4.1.3',
		'8.4.1.11',
		'8.4.2',
		'8.4.2.1',
		'8.4.2.8',
		'8.4.3',
		'8.4.3.8',
		'8.4.3.9',
		'8.4.4',
		'8.4.4.1',
		'8.4.4.3',
		'8.4.4.5',
		'8.4.4.9',
		'8.4.5',
		'8.4.5.6',
		'8.4.6',
		'8.4.7',
		'8.4.7.3',
		'8.4.7.15',
		'8.4.7.22',
		'8.4.7.23',
		'8.4.7.26',
		'8.4.7.28',
		'8.4.0',
		'8.4.7.29',
		'8.5.1',
		'8.5.1.1',
		'8.5.1.6',
		'8.5.1.7',
		'8.5.1.14',
		'8.5.1.17',
		'8.5.1.18',
		'8.5.1.19',
		'8.5.1.24',
		'8.5.1.21',
		'8.6.1',
		'8.6.1.1',
		'8.6.1.2',
		'8.6.1.5',
		'8.6.1.10',
		'8.6.1.12',
		'8.6.1.13',
		'8.6.1.17',
		'8.6.1.14',
		'8.7.1',
		'8.7.1.1',
		'8.7.1.3',
		'8.7.1.4',
		'8.7.1.7',
		'8.7.1.8',
		'8.7.1.11',
		'8.7.1.13',
		'8.7.1.16',
		'8.7.1.17',
		'9.0.1',
		'9.0.2',
		'9.0.2.10',
		'9.0.3',
		'9.0.3.6',
		'9.0.3.8',
		'9.0.4',
		'9.0.4.1',
		'9.0.4.5',
		'9.0.4.7',
		'9.0.4.17',
		'9.0.4.20',
		'9.0.4.24',
		'9.0.4.26',
		'9.0.4.29',
		'9.0.4.33',
		'9.0.4.35',
		'9.0.4.37',
		'9.1.1',
		'9.1.1.4',
		'9.1.2',
		'9.1.2.8',
		'9.1.3',
		'9.1.3.2',
		'9.1.4',
		'9.1.4.5',
		'9.1.5',
		'9.1.5.10',
		'9.1.5.12',
		'9.1.5.15',
		'9.1.5.21',
		'9.1.6',
		'9.1.6.1',
		'9.1.6.4',
		'9.1.6.6',
		'9.1.6.8',
		'9.1.6.10',
		'9.2.1',
		'9.2.2',
		'9.2.2.4',
		'9.2.2.7',
		'9.2.2.8',
		'9.2.3',
		'9.2.3.3',
		'9.2.3.4',
		'9.2.0.0',
		'9.2.0.104',
		'9.2.3.1',
		'9.2.4',
		'9.2.4.2',
		'9.2.4.4',
		'9.3.1',
		'9.3.1.1',
		'9.3.2',
		'9.3.2.2',
		'9.3.3',
		'9.3.3.1',
		'9.3.3.2',
		'9.3.3.5',
		'9.3.1.105',
		'9.3.2.100',
		'9.3.3.6',
		'9.3.2.243',
		'9.3.1.50',
		'9.3.5',
		'9.4.1',
		'9.4.0.115',
		'9.4.1.1',
		'9.4.1.2',
		'9.4.1.3',
		'9.4.1.5',
		'9.4.2',
		'9.4.2.3',
		'9.5.1',
		'9.5.2' );

foreach af ( affected )
{
  if( check_vers == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

