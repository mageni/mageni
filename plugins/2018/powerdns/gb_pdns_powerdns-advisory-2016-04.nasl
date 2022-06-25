##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pdns_powerdns-advisory-2016-04.nasl 12447 2018-11-21 04:17:12Z ckuersteiner $
#
# PowerDNS Security Advisory 2016-04: Insufficient validation of TSIG signatures
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
  script_oid("1.3.6.1.4.1.25623.1.0.112374");
  script_version("$Revision: 12447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 05:17:12 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-09-12 16:54:11 +0200 (Wed, 12 Sep 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2016-7073", "CVE-2016-7074");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PowerDNS Security Advisory 2016-04: Insufficient validation of TSIG signatures");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("pdns_version.nasl");
  script_mandatory_keys("powerdns/recursor_or_authoritative_server/installed");

  script_tag(name:"summary", value:"Two issues have been found in PowerDNS Authoritative Server allowing
an attacker in position of man-in-the-middle to alter the content of an AXFR because of insufficient validation
of TSIG signatures. The first issue is a missing check of the TSIG time and fudge values in AXFRRetriever, leading
to a possible replay attack. This issue has been assigned CVE-2016-7073.

The second issue is a missing check that
the TSIG record is the last one, leading to the possibility of parsing records that are not covered by the TSIG signature.
This issue has been assigned CVE-2016-7074.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PowerDNS Authoritative Server up to and including 3.4.10 and 4.0.1 are affected.
PowerDNS Recursor from 4.0.0 up to and including 4.0.3 are affected.");

  script_tag(name:"solution", value:"Update PowerDNS Authoritative Server to version 3.4.11 or 4.0.2 respectively.
  Update PowerDNS Recursor 4.x.x to version 4.0.4.");

  script_xref(name:"URL", value:"https://doc.powerdns.com/md/security/powerdns-advisory-2016-04/");

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
  if( version_in_range( version:version, test_version:"4.0.0", test_version2:"4.0.3" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"4.0.4" );
    security_message( data:report, port:port, proto:proto );
    exit( 0 );
  }
}

exit( 99 );
