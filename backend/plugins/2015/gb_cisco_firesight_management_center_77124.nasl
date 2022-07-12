###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firesight_management_center_77124.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco FireSIGHT Management Center for VMware Security Bypass Vulnerability
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

CPE = "cpe:/a:cisco:firesight_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105428");
  script_bugtraq_id(77124);
  script_cve_id("CVE-2015-6335");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco FireSIGHT Management Center for VMware Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77124");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151016-fmc");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass security restrictions to perform unauthorized actions. This may aid in launching
further attacks.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability is due to insufficient sanitization of user-supplied input. An attacker could exploit this vulnerability by bypassing policy restrictions
and executing commands on the underlying operating system. The user needs to log in to the device with valid administrator-level credentials.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");
  script_tag(name:"summary", value:"Cisco FireSIGHT Management Center for VMware is prone to a security-bypass vulnerability.");
  script_tag(name:"affected", value:"Cisco FireSIGHT Management Center for VMware versions 5.3.1.7, 5.4.0.4, and 6.0.0 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-29 13:50:58 +0100 (Thu, 29 Oct 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firesight_management_center_version.nasl");
  script_mandatory_keys("cisco_firesight_management_center/version", "cisco_firesight_management_center/model");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

model = get_kb_item( "cisco_firesight_management_center/model" );
if( ! model || model != "VM" ) exit( 99 );

if( version_in_range( version:version, test_version:"5.3.1", test_version2:"5.3.1.7") ) VULN = TRUE;
if( version_in_range( version:version, test_version:"5.4.0", test_version2:"5.4.0.4") ) VULN = TRUE;
if( version == "6.0.0" ) VULN = TRUE;

if( VULN )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     See vendor advisory';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

