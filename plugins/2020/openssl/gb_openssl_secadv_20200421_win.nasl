# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108752");
  script_version("2020-04-22T06:06:21+0000");
  script_cve_id("CVE-2020-1967");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-04-22 10:04:52 +0000 (Wed, 22 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-22 06:05:59 +0000 (Wed, 22 Apr 2020)");
  script_name("OpenSSL: Segmentation fault in SSL_check_chain (CVE-2020-1967) (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20200421.txt");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=eb563247aef3e83dda7679c43f9649270462e5b1");

  script_tag(name:"summary", value:"OpenSSL server or client applications are prone to a
  denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Server or client applications that call the SSL_check_chain() function
  during or after a TLS 1.3 handshake may crash due to a NULL pointer dereference as a result of incorrect
  handling of the 'signature_algorithms_cert' TLS extension. The crash occurs if an invalid or unrecognised
  signature algorithm is received from the peer.");

  script_tag(name:"impact", value:"This could be exploited by a malicious peer in a Denial of
  Service attack.");

  script_tag(name:"affected", value:"OpenSSL versions 1.1.1d, 1.1.1e, and 1.1.1f.

  This issue does not impact OpenSSL versions prior to 1.1.1d.");

  script_tag(name:"solution", value:"Update OpenSSL to version 1.1.1g or later. See the references for more details.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"1.1.1d", test_version2:"1.1.1f" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.1g", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
