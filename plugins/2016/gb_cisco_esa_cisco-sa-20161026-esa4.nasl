###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_esa_cisco-sa-20161026-esa4.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco Email Security Appliance Quarantine Email Rendering Vulnerability
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

CPE = "cpe:/h:cisco:email_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140026");
  script_cve_id("CVE-2016-1423");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12313 $");

  script_name("Cisco Email Security Appliance Quarantine Email Rendering Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-esa4");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the display of email messages in the Messages in Quarantine (MIQ) view in Cisco
  AsyncOS for Cisco Email Security Appliance (ESA) could allow an unauthenticated, remote attacker to
  cause a user to click a malicious link in the MIQ view. The malicious link could be used to
  facilitate a cross-site scripting (XSS) or HTML injection attack.

  The vulnerability is due to malformed HTML script tags in quarantined email messages. An attacker
  could exploit this vulnerability by sending a crafted email message to the affected device. An
  exploit could allow the attacker to trick a user who views the MIQ email message into clicking a
  malicious link.

  Cisco has not released software updates that address this vulnerability. There are no workarounds
  that address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-27 14:10:54 +0200 (Thu, 27 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_esa_version.nasl");
  script_mandatory_keys("cisco_esa/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'8.9.0',
		'8.9.1-000',
		'8.9.2-032',
		'9.0.0',
		'9.0.0-212',
		'9.0.0-461',
		'9.0.5-000',
		'9.1.0',
		'9.1.0-011',
		'9.1.0-101',
		'9.1.0-032' );

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

