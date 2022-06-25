###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cobbler_mult_vuln.nasl 14078 2019-03-11 03:25:53Z ckuersteiner $
#
# Cobbler <= 2.6.11+ Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112358");
  script_version("$Revision: 14078 $");
  script_cve_id("CVE-2018-1000225", "CVE-2018-1000226");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 04:25:53 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-08-21 09:48:12 +0200 (Tue, 21 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cobbler <= 2.6.11+ Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Cobbler and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws consist of a persistent XSS vulnerability and an incorrect authentication vulnerability.");

  script_tag(name:"affected", value:"Cobbler versions up to and including 2.6.11.");

  script_tag(name:"solution", value:"No known solution is available as of 11th March, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL", value:"https://movermeyer.com/2018-08-02-privilege-escalation-exploits-in-cobblers-api/");
  script_xref(name:"URL", value:"https://github.com/cobbler/cobbler/issues/1916");
  script_xref(name:"URL", value:"https://github.com/cobbler/cobbler/issues/1917");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_cobbler_detect.nasl");
  script_mandatory_keys("Cobbler/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

CPE = "cpe:/a:michael_dehaan:cobbler";

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

if( version_is_less_equal( version: version, test_version: "2.6.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
