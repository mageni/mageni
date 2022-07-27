##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dnsmasq_dos_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Dnsmasq DoS Vulnerability
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
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:thekelleys:dnsmasq';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106095");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-15 12:45:27 +0700 (Wed, 15 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2015-8899");
  script_name("Dnsmasq DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("dnsmasq_version.nasl");
  script_mandatory_keys("dnsmasq/installed");

  script_xref(name:"URL", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
  script_xref(name:"URL", value:"http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2016q2/010479.html");

  script_tag(name:"summary", value:"Dnsmasq is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Dnsmasq crashes when an A or AAAA record is defined locally,
  in a hosts file, and an upstream server sends a reply that the same name is empty.");

  script_tag(name:"impact", value:"A remote attacker may cause a DoS condition.");

  script_tag(name:"affected", value:"Dnsmasq 2.73 until 2.75");

  script_tag(name:"solution", value:"Upgrade to version 2.76 or later");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_in_range( version:version, test_version:"2.73", test_version2:"2.75" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.76" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
