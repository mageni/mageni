###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firesight_cisco-sa-20160302-FireSIGHT.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Cisco FireSIGHT System Software Multiple Vulnerabilities
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

CPE = "cpe:/a:cisco:firesight_management_center";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105582");
  script_cve_id("CVE-2016-1356", "CVE-2016-1355");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 14181 $");

  script_name("Cisco FireSIGHT System Software Multiple Vulnerabilities");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-FireSIGHT");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160302-FireSIGHT1");

  script_tag(name:"impact", value:"An attacker could exploit the XSS vulnerability by persuading a user to click a specific link.
  An attacker could exploit the Convert Timing Channel vulnerability by using a combination of valid system logins, invalid system
  logins, and time variability to try to continuously authenticate to a device.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The XSS vulnerability is due to improper sanitization of parameter values. The Convert Timing Channel
  Vulnerability is due to implementation details of how system credentials are verified by the affected software.");

  script_tag(name:"solution", value:"See vendor advisory");
  script_tag(name:"summary", value:"A vulnerability in credential authentication for valid and invalid username-password pairs for Cisco
  FireSIGHT System Software could allow an unauthenticated, remote attacker to determine a list of valid usernames for an affected device.
  A vulnerability in the HTTP web-based management interface of Cisco FireSIGHT System Software could allow an unauthenticated, remote attacker
  to conduct a cross-site scripting (XSS) attack against a user of the web interface of an affected system.");
  script_tag(name:"affected", value:"Cisco FireSIGHT System Software Release 6.1.0 is vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-21 13:46:30 +0100 (Mon, 21 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firesight_management_center_version.nasl", "gb_cisco_firesight_management_center_http_detect.nasl");
  script_mandatory_keys("cisco_firesight_management_center/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version == '6.1.0' )
{
  report = report_fixed_ver( installed_version:version, fixed_version:"See advisory" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );