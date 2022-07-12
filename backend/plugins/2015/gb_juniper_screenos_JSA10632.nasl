###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_juniper_screenos_JSA10632.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Juniper NetScreen Firewall DNS lookup/Malformed IPv6 packet Denial of Service Vulnerability
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

CPE = "cpe:/o:juniper:screenos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105270");
  script_bugtraq_id(68100, 68099);
  script_cve_id("CVE-2014-3814");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Juniper NetScreen Firewall DNS lookup/Malformed IPv6 packet Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10632");

  script_tag(name:"impact", value:"Successful exploits may allow the attacker to cause denial-of-service conditions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A Denial of Service (DoS) issue has been
found in Juniper Networks NetScreen Firewall products. When
encountered, this issue can cause the device to crash and reboot. If
an attacker were to repeatedly exploit the issue a sustained denial
of service could take place on the device. The issue is caused when
a certain sequence of malformed IPv6 packets are sent to the
device's IP directly. This issue will not take place if the packets
are traversing the network through the firewall.");

  script_tag(name:"solution", value:"Updates are available. Please see the references or
vendor advisory for more information.");

  script_tag(name:"summary", value:"Juniper NetScreen Firewall is prone to a denial-of-service vulnerability.");
  script_tag(name:"affected", value:"ScreenOS 6.3 prior to 6.3.0r17");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-08 15:40:14 +0200 (Fri, 08 May 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_screenos_version.nasl");
  script_mandatory_keys("ScreenOS/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  if( ! version = get_kb_item("ScreenOS/version") ) exit( 0 );

if( version !~ "^6\.3\." ) exit( 99 );

display_fix = '6.3.0r17';
display_version = version;

fix = str_replace( string:display_fix, find:"r", replace:"." );
version = str_replace( string:version, find:"r", replace:"." );

if( version_is_less( version:version, test_version:fix ) )
{
  report = 'Installed version: ' + display_version + '\n' +
           'Fixed version:     ' + display_fix + '\n';

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


