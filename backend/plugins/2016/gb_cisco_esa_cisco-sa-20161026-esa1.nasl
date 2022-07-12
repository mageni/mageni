###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_esa_cisco-sa-20161026-esa1.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco Email Security Appliance Malformed DGN File Attachment Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.140029");
  script_cve_id("CVE-2016-1481");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12051 $");

  script_name("Cisco Email Security Appliance Malformed DGN File Attachment Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161026-esa1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the email message filtering feature of Cisco AsyncOS Software for Cisco Email
  Security Appliances could allow an unauthenticated, remote attacker to cause a denial of service
  (DoS) condition on an affected device.

  The vulnerability exists because the message filtering feature of the affected software does not
  properly validate compressed message attachments that contain malformed Design (DGN) files. An
  attacker could exploit this vulnerability by sending a crafted email message, which has a compressed
  attachment containing a malformed DGN file, through an affected device. While the affected software
  filters the attachment, memory could be consumed at a high rate and ultimately exhausted, causing
  the filtering process to restart and resulting in a DoS condition. After the filtering process
  restarts, the software resumes filtering for the same attachment, causing the filtering process to
  exhaust memory and restart again. A successful exploit of this vulnerability could allow the
attacker to cause a repeated DoS condition.

  Cisco has released software updates that address this vulnerability. There are no workarounds that
  address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-27 14:14:28 +0200 (Thu, 27 Oct 2016)");
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
		'8.5.0-000',
		'8.5.0-ER1-198',
		'8.5.6-052',
		'8.5.6-073',
		'8.5.6-074',
		'8.5.6-106',
		'8.5.6-113',
		'8.5.7-042',
		'8.6.0',
		'8.6.0-011',
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
		'9.1.0-032',
		'9.1.1-000',
		'9.4.0',
		'9.4.4-000',
		'9.5.0-000',
		'9.5.0-201',
		'9.6.0-000',
		'9.6.0-042',
		'9.6.0-051',
		'9.7.0-125' );

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

