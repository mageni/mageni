###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_matrixssl_side_channel_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# MatrixSSL (GUARD TLS-TK) Side-Channel Attack Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113210");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-19 13:07:40 +0200 (Tue, 19 Jun 2018)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-12439");

  script_name("MatrixSSL (GUARD TLS-TK) Side-Channel Attack Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("gb_matrixssl_detect.nasl");
  script_mandatory_keys("matrixssl/installed");

  script_tag(name:"summary", value:"GUARD TLS-TK (formerly MatrixSSL) is vulnerable to a Memory-Cache Side-Channel attack.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is located in the code that computes signature component 's'.
  In many libraries, the code that performs modular addition does not
  run in constant time, and so a side channel can recover information
  that can be used to calculate the private key.");
  script_tag(name:"impact", value:"A local attacker might use the vulnerability to acquire SSH keys
  or TLS private keys.");
  script_tag(name:"affected", value:"MatrixSSL through version 3.9.5.");
  script_tag(name:"solution", value:"Update to version 3.9.6 once released.
  Contact the vendor at support@matrixssl.org to get a fix until then.");

  script_xref(name:"URL", value:"https://www.nccgroup.trust/us/our-research/technical-advisory-return-of-the-hidden-number-problem/");

  exit(0);
}

CPE = "cpe:/a:peersec_networks:matrixssl:";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less_equal( version: version, test_version: "3.9.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.9.6 or contact the vendor" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
