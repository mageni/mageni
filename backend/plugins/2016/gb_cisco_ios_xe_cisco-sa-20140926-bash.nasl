###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20140926-bash.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# GNU Bash Environment Variable Command Injection Vulnerability
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105684");
  script_cve_id("CVE-2014-6271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12149 $");

  script_name("GNU Bash Environment Variable Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35836");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35880");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35845");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35879");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35860");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35861");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=35816");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"On September 24, 2014, a vulnerability in the Bash shell was publicly announced.
  The vulnerability is related to the way in which shell functions are passed though environment variables.
  The vulnerability may allow an attacker to inject commands into a Bash shell, depending on how the shell is invoked.
  The Bash shell may be invoked by a number of processes including, but not limited to, telnet, SSH, DHCP, and scripts hosted on web servers.

  All versions of GNU Bash starting with version 1.14 are affected by this vulnerability and the specific impact is determined
  by the characteristics of the process using the Bash shell. In the worst case, an unauthenticated remote attacker would be able
  to execute commands on an affected server. However, in most cases involving Cisco products, authentication is required before exploitation could be attempted.

  A number of Cisco products ship with or use an affected version of the Bash shell. The Bash shell is a third-party software component
  that is part of the GNU software project and used by a number of software vendors. As of this version of the Security Advisory,
  there have been a number of vulnerabilities recently discovered in the Bash shell, and the investigation is ongoing. For vulnerable products,
  Cisco has included information on the product versions that will contain the fixed software, and the date these versions are expected
  to be published on the cisco.com download page. This advisory will be updated as additional information becomes available.
  Cisco may release free software updates that address this vulnerability if a product is determined to be affected by this vulnerability.
  This advisory is available at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-10 11:04:49 +0200 (Tue, 10 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'2.1.0',
		'2.1.1',
		'2.1.2',
		'2.2.1',
		'2.2.2',
		'2.2.3',
		'2.3.0',
		'2.3.0t',
		'2.3.1t',
		'2.3.2',
		'2.4.0',
		'2.4.1',
		'2.5.0',
		'2.6.0',
		'2.6.1',
		'2.6.2',
		'3.1.0S',
		'3.1.1S',
		'3.1.2S',
		'3.1.3S',
		'3.1.1SG',
		'3.2.0S',
		'3.2.1S',
		'3.2.2S',
		'3.2.0SE',
		'3.2.1SE',
		'3.2.2SE',
		'3.2.3SE',
		'3.2.0SG',
		'3.2.1SG',
		'3.2.2SG',
		'3.2.3SG',
		'3.2.4SG',
		'3.2.5SG',
		'3.2.0XO',
		'3.2.1XO',
		'3.3.0S',
		'3.3.1S',
		'3.3.2S',
		'3.3.0SE',
		'3.3.1SE',
		'3.3.0SG',
		'3.3.1SG',
		'3.3.2SG',
		'3.3.0XO',
		'3.4.0S',
		'3.4.1S',
		'3.4.2S',
		'3.4.3S',
		'3.4.4S',
		'3.4.5S',
		'3.4.6S',
		'3.4.0SG',
		'3.4.1SG',
		'3.4.2SG',
		'3.5.0E',
		'3.5.0S',
		'3.5.1S',
		'3.5.2S',
		'3.6.0S',
		'3.6.1S',
		'3.6.2S',
		'3.7.0S',
		'3.7.1S',
		'3.7.2S',
		'3.7.3S',
		'3.7.4S',
		'3.7.5S',
		'3.7.6S',
		'3.8.0S',
		'3.8.1S',
		'3.8.2S',
		'3.9.0S',
		'3.9.1S',
		'3.9.2S',
		'3.10.0S',
		'3.10.0S',
		'3.10.1S',
		'3.10.2S',
		'3.10.3S',
		'3.10.4S',
		'3.11.0S',
		'3.11.1S',
		'3.11.2S',
		'3.12.0S',
		'3.13.0S' );

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

