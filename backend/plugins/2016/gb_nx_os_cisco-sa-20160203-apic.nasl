###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nx_os_cisco-sa-20160203-apic.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Cisco Application Policy Infrastructure Controller Access Control Vulnerability (Nexus 9xxx)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105547");
  script_cve_id("CVE-2016-1302");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("$Revision: 14181 $");

  script_name("Cisco Application Policy Infrastructure Controller Access Control Vulnerability (Nexus 9xxx)");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160203-apic");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-02-15 18:02:24 +0100 (Mon, 15 Feb 2016)");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_nx_os_version.nasl");
  script_mandatory_keys("cisco_nx_os/version", "cisco_nx_os/model", "cisco_nx_os/device");

  script_tag(name:"impact", value:"An authenticated user could exploit this vulnerability by sending specially
  crafted representational state transfer (REST) requests to the APIC. An exploit could allow the authenticated
  user to make configuration changes to the APIC beyond the configured privilege for their role.");
  script_tag(name:"vuldetect", value:"Check the NX OS version.");
  script_tag(name:"insight", value:"The vulnerability is due to eligibility logic in the RBAC processing code.");
  script_tag(name:"solution", value:"See the vendor advisory for a solution");
  script_tag(name:"summary", value:"A vulnerability in the role-based access control (RBAC) of the Cisco Application Policy
  Infrastructure Controller (APIC) could allow an authenticated remote user to make configuration changes outside of their configured access privileges.");
  script_tag(name:"affected", value:"Cisco Nexus 9000 Series ACI Mode Switches when running software versions prior to 11.0(3h) and 11.1(1j)");

  exit(0);
}

include("version_func.inc");

if( ! device = get_kb_item( "cisco_nx_os/device" ) ) exit( 0 );
if( "Nexus" >!< device ) exit( 0 );

if( ! nx_model = get_kb_item( "cisco_nx_os/model" ) )   exit( 0 );
if( nx_model !~ '^N9K' ) exit( 99 );

if( ! nx_ver = get_kb_item( "cisco_nx_os/version" ) ) exit( 0 );

_build = eregmatch( pattern:"^[0-9.]+\(([0-9.]+)", string:nx_ver );
if( ! isnull( _build[1] ) ) build = _build[1];

if( ! build ) exit( 0 );

if( nx_ver =~ "^11\.0" )
  if( int( build ) < int( 3 ) ) fix = '11.0(3h)';

if( nx_ver =~ "^11\.1" )
  if( int( build ) < int( 1 ) ) fix = '11.1(1j)';

if( fix )
{
  report = report_fixed_ver(  installed_version:nx_ver, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );