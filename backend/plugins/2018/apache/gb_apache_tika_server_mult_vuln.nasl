###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tika_server_mult_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# Apache Tika Server 1.17 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113167");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-26 11:12:13 +0200 (Thu, 26 Apr 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-1335", "CVE-2018-1338", "CVE-2018-1339");

  script_name("Apache Tika Server 1.17 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tika_server_detect.nasl");
  script_mandatory_keys("Apache/Tika/Server/Installed");

  script_tag(name:"summary", value:"Apache Tika Server is prone to multiple vulnerabilities,
  including Command Execution and Denial of Service");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  In Apache Tika, clients could send carefully crafted headers to tika-server that could be used to inject commands
  into the command line of the server running tika-server.
  This vulnerability only affects those running tika-server on a server that is open to untrusted clients.

  A carefully crafted (or fuzzed) file can trigger an infinite loop in Apache Tika's BPGParser.

  A carefully crafted (or fuzzed) file can trigger an infinite loop in Apache Tika's ChmParser.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to eventually gain full control
  over the target system.");
  script_tag(name:"affected", value:"Apache Tika Server through version 1.17.");
  script_tag(name:"solution", value:"Update to version 1.18.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/b3ed4432380af767effd4c6f27665cc7b2686acccbefeb9f55851dca@%3Cdev.tika.apache.org%3E");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/4d20c5748fb9f836653bc78a1bad991ba8485d82a1e821f70b641932@%3Cdev.tika.apache.org%3E");

  exit(0);
}

CPE = "cpe:/a:apache:tika";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "1.18" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.18" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
