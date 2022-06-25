##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nsd_dos_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# NSD (Name Server Daemon) AXFR Response Denial of Service Vulnerability
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

CPE = "cpe:/a:nlnetlabs:nsd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106121");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-08 10:27:46 +0700 (Fri, 08 Jul 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2016-6173");
  script_name("NSD (Name Server Daemon) AXFR Response Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("nsd_version.nasl");
  script_mandatory_keys("nsd/installed");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/07/06/3");
  script_xref(name:"URL", value:"https://lists.dns-oarc.net/pipermail/dns-operations/2016-July/015058.html");
  script_xref(name:"URL", value:"http://www.nlnetlabs.nl/svn/nsd/trunk/doc/RELNOTES");

  script_tag(name:"summary", value:"NSD (Name Server Daemon) is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Primary DNS servers may cause a denial of service (secondary DNS server
  crash) via a large AXFR response, and possibly allows IXFR servers to cause a denial of service (IXFR client
  crash) via a large IXFR response and allows remote authenticated users to cause a denial of service (primary
  DNS server crash) via a large UPDATE message");

  script_tag(name:"impact", value:"An authenticated remote attacker may cause a denial of service
  condition.");

  script_tag(name:"affected", value:"Version <= 4.1.10");

  script_tag(name:"solution", value:"Update to version 4.1.11.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/projects/nsd/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less_equal( version:version, test_version:"4.1.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.1.11" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
