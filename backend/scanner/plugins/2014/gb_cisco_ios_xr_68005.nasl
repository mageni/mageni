###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_68005.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Cisco IOS XR Software IPv6 Packet Handling  Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105080");
  script_bugtraq_id(68005);
  script_cve_id("CVE-2014-2176");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 11867 $");

  script_name("Cisco IOS XR Software IPv6 Packet Handling Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68005");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140611-ipv6");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause NP chip and a line card on
an affected device to lockup and reload, denying service to legitimate users.");

  script_tag(name:"vuldetect", value:"Check the IOS XR Version");

  script_tag(name:"insight", value:"This issue is being tracked by Cisco Bug ID CSCun71928");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Cisco IOS XR is prone to a remote denial-of-service vulnerability.");
  script_tag(name:"affected", value:"This issue is being tracked by Cisco Bug ID CSCun71928.");


  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-09-04 10:43:53 +0200 (Thu, 04 Sep 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xr_detect_snmp.nasl");
  script_mandatory_keys("cisco/ios_xr/version", "cisco/ios_xr/model");

  exit(0);
}

include("host_details.inc");

get_app_version( cpe:CPE );

if ( ! model = get_kb_item( "cisco/ios_xr/model" ) ) exit( 0 );
if ( ! ver   = get_kb_item( "cisco/ios_xr/version" ) ) exit( 0 );

if( "ASR9K" >!< model ) exit( 99 );

if( ver =~ "^3\.[79]\.[0-3]$" || ver =~ "^3\.8\.[0-4]$" || ver =~ "^4\.0\.[0-4]$" ||
    ver =~ "^4\.1\.[0-2]$" || ver =~ "^4\.2\.[0-4]$" || ver =~ "^4\.3\.[0-4]$" ||
    ver =~ "^5\.1\.[01]$" )
{
  report = 'Cisco Bug ID:      CSCun71928\nInstalled Version: ' + ver;
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
