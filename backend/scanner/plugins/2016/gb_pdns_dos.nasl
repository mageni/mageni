##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pdns_dos.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# PowerDNS Authoritative Server DoS Vulnerability
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

CPE = 'cpe:/a:powerdns:authoritative_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106094");
  script_version("$Revision: 12363 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-08 11:23:10 +0700 (Wed, 08 Jun 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2015-5311");
  script_name("PowerDNS Authoritative Server DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/authoritative_server/installed");

  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2015-03/");

  script_tag(name:"summary", value:"PowerDNS Authoritative Server is prone to a denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A bug was found in the packet parsing code. This bug, when exploited,
  causes an assertion error and consequent termination of the the pdns_server process, causing a Denial of Service.

  When the PowerDNS Authoritative Server is run inside the guardian (--guardian), or inside a supervisor
  like supervisord or systemd, it will be automatically restarted, limiting the impact to a somewhat
  degraded service.");

  script_tag(name:"impact", value:"A remote attacker may cause a DoS condition.");

  script_tag(name:"affected", value:"PowerDNS Authoritative Server 3.4.4 until 3.4.6");

  script_tag(name:"solution", value:"Upgrade to version 3.4.7 or later");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"3.4.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.7" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );