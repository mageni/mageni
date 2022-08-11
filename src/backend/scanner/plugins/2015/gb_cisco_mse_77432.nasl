###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_mse_77432.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco Mobility Services Engine Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:mobility_services_engine";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105463");
  script_bugtraq_id(77432, 77435);
  script_cve_id("CVE-2015-6316", "CVE-2015-4282");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco Mobility Services Engine Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-privmse");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-mse-cred");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This issues are being tracked by Cisco Bug ID CSCuv40501 and CSCuv40504");
  script_tag(name:"solution", value:"Updates are available.");
  script_tag(name:"summary", value:"Cisco Mobility Services Engine is prone to the following vulnerabilities:
1. an insecure default-password vulnerability.
Remote attackers with knowledge of the default credentials may exploit this vulnerability to gain unauthorized access and perform unauthorized actions. This may aid in further attacks.

2. a local privilege-escalation vulnerability.
A local attacker may exploit this issue to gain elevated root privileges on the device.");

  script_tag(name:"affected", value:"Cisco Mobility Services Engine (MSE) versions 8.0.120.7 and earlier are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 14:02:20 +0100 (Fri, 20 Nov 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_mse_cmx_version.nasl");
  script_mandatory_keys("cisco_mse/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less_equal( version:version, test_version:"8.0.120.7" ) )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     See vendor advisory';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
