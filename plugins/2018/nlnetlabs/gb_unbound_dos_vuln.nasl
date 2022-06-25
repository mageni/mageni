###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unbound_dos_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Unbound DNS Resolver Denial of Service Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113091");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-24 15:09:10 +0100 (Wed, 24 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-15105");

  script_name("Unbound DNS Resolver Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"A flaw was found in the way unbound before 1.6.8 validated wildcard-synthesized NSEC records. An improperly validated wildcard NSEC record could be used to prove the non-existence (NXDOMAIN answer) of an existing wildcard record, or trick unbound into accepting a NODATA proof.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"Unbound DNS Resolver before version 1.6.8");
  script_tag(name:"solution", value:"Update to version 1.6.8 or above");

  script_xref(name:"URL", value:"https://unbound.net/downloads/CVE-2017-15105.txt");

  exit(0);
}

CPE = "cpe:/a:unbound:unbound";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe: CPE, port: port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version: version, test_version: "1.6.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.6.8" );
  security_message( data: report, port: port, proto: proto );
  exit( 0 );
}

exit( 99 );
