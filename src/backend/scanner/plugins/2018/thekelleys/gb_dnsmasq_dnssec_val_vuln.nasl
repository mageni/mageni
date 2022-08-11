##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dnsmasq_dnssec_val_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Dnsmasq DNSSEC Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112193");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-25 12:15:27 +0100 (Thu, 25 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2017-15107");
  script_name("Dnsmasq DNSSEC Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("dnsmasq_version.nasl");
  script_mandatory_keys("dnsmasq/installed");

  script_xref(name:"URL", value:"http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2018q1/011896.html");
  script_xref(name:"URL", value:"http://thekelleys.org.uk/dnsmasq/CHANGELOG");

  script_tag(name:"summary", value:"Dnsmasq is prone to an improper DNSSEC validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Wildcard synthesized NSEC records could be improperly interpreted to prove the non-existence of hostnames that actually exist.");

  script_tag(name:"affected", value:"Dnsmasq up to and including version 2.78");

  script_tag(name:"solution", value:"Update to version 2.79 or later. Please see the references for more information.");

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

if( version_is_less( version:version, test_version:"2.79" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.79" );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
