##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pdns_powerdns-advisory-2016-02.nasl 12447 2018-11-21 04:17:12Z ckuersteiner $
#
# PowerDNS Security Advisory 2016-02: Crafted queries can cause abnormal CPU usage
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of their respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112375");
  script_version("$Revision: 12447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 05:17:12 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-12 16:54:11 +0200 (Wed, 12 Sep 2018)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2016-7068");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Security Advisory 2016-02: Crafted queries can cause abnormal CPU usage");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor_or_authoritative_server/installed");

  script_tag(name:"summary", value:"An issue has been found in PowerDNS allowing a remote,
unauthenticated attacker to cause an abnormal CPU usage load on the PowerDNS server by sending
crafted DNS queries, which might result in a partial denial of service if the system becomes overloaded.
This issue is based on the fact that the PowerDNS server parses all records present in a query
regardless of whether they are needed or even legitimate. A specially crafted query containing a
large number of records can be used to take advantage of that behaviour.
This issue has been assigned CVE-2016-7068.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative Server up to and including 3.4.10 and 4.0.1 are affected.
  PowerDNS Recursor up to and including 3.7.3 and 4.0.3 are affected.");

  script_tag(name:"solution", value:"Update PowerDNS Authoritative Server to version 3.4.11 or 4.0.2 respectively.
  Update PowerDNS Recursor to 3.7.4 or 4.0.4 respectively.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-02/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( 'cpe:/a:powerdns:authoritative_server', 'cpe:/a:powerdns:recursor' );

if( ! list_infos = get_all_app_ports_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe = list_infos['cpe'];
port = list_infos['port'];

if( ! infos = get_app_version_and_proto( cpe:cpe, port:port ) )
  exit( 0 );

version = infos['version'];
proto = infos['proto'];

if( cpe == 'cpe:/a:powerdns:authoritative_server' ) {
  if( version_is_less( version:version, test_version:"3.4.11" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"3.4.11" );
    security_message( data:report, port:port, proto:proto );
    exit( 0 );
  }
  if( version_is_equal( version:version, test_version:"4.0.1" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"4.0.2" );
    security_message( data:report, port:port, proto:proto );
    exit( 0 );
  }
} else if ( cpe == 'cpe:/a:powerdns:recursor' ) {
  if( version_is_less( version:version, test_version:"3.7.3" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"3.7.4" );
    security_message( data:report, port:port, proto:proto );
    exit( 0 );
  }
  if( version_is_equal( version:version, test_version:"4.0.3" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"4.0.4" );
    security_message( data:report, port:port, proto:proto );
    exit( 0 );
  }
}

exit( 99 );
