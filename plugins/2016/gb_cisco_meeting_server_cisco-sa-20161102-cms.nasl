###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_meeting_server_cisco-sa-20161102-cms.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco Meeting Server Buffer Underflow Vulnerability
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

CPE = "cpe:/a:cisco:meeting_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106372");
  script_cve_id("CVE-2016-6447");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12096 $");

  script_name("Cisco Meeting Server Buffer Underflow Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-cms");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 2.0.1 or later.");

  script_tag(name:"summary", value:"A vulnerability in Cisco Meeting Server could allow an unauthenticated,
remote attacker to execute arbitrary code on an affected system.");

  script_tag(name:"insight", value:"The vulnerability exists because the software does not perform sufficient
boundary checks on user-supplied data. An unauthenticated, remote attacker could exploit this vulnerability by
sending crafted IPv6 input to the vulnerable function.");

  script_tag(name:"impact", value:"A successful exploit could result in an exploitable buffer underflow
condition. An attacker could leverage this buffer underflow condition to incorrectly allocate memory and cause
a reload of the device or execute arbitrary code with the privileges of the affected application.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-11-03 14:19:37 +0700 (Thu, 03 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_meeting_server_snmp_detect.nasl");
  script_mandatory_keys("cisco/meeting_server/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'1.8.0',
		'1.9.0',
		'2.0.0' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "2.0.1" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

