###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wsa_cisco-sa-20160627-wsa.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco Web Security Appliance Native FTP Denial of Service Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/h:cisco:web_security_appliance";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105779");
  script_cve_id("CVE-2016-1440");
  script_version("$Revision: 12096 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-28 14:05:06 +0200 (Tue, 28 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cisco Web Security Appliance Native FTP Denial of Service Vulnerability");

  script_tag(name:"summary", value:"A vulnerability in the native pass-through FTP functionality of the Cisco Web Security Appliance (WSA) could allow an unauthenticated, remote attacker to cause a partial denial of service (DoS) condition due to high CPU utilization.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Cisco WSA < 9.1.1-041");

  script_tag(name:"solution", value:"Update to 9.1.1-041 or newer");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160627-wsa");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_wsa_version.nasl");
  script_mandatory_keys("cisco_wsa/version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

version = str_replace( string:vers, find:"-", replace:"." );

if( version_is_less( version:version, test_version:'9.1.1.041' ) )
{
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.1.1-041" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
