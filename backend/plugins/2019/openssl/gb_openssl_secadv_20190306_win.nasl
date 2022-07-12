# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108609");
  script_version("2019-07-03T06:18:14+0000");
  script_cve_id("CVE-2019-1543");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-07-03 06:18:14 +0000 (Wed, 03 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-03 06:06:21 +0000 (Wed, 03 Jul 2019)");
  script_name("OpenSSL: ChaCha20-Poly1305 with long nonces (CVE-2019-1543) (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20190306.txt");
  script_xref(name:"URL", value:"https://seclists.org/bugtraq/2019/Jul/3");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ee22257b1418438ebaf54df98af4e24f494d1809");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=f426625b6ae9a7831010750490a5f0ad689c5ba3");
  script_xref(name:"URL", value:"https://www.openssl.org/news/cl111.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/cl110.txt");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to vulnerability which allows a nonce reuse.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"ChaCha20-Poly1305 is an AEAD cipher, and requires
  a unique nonce input for every encryption operation. RFC 7539 specifies that the
  nonce value (IV) should be 96 bits (12 bytes). OpenSSL allows a variable nonce
  length and front pads the nonce with 0 bytes if it is less than 12 bytes. However
  it also incorrectly allows a nonce to be set of up to 16 bytes. In this case only
  the last 12 bytes are significant and any additional leading bytes are ignored.

  It is a requirement of using this cipher that nonce values are unique. Messages
  encrypted using a reused nonce value are susceptible to serious confidentiality
  and integrity attacks. If an application changes the default nonce length to be
  longer than 12 bytes and then makes a change to the leading bytes of the nonce
  expecting the new value to be a new unique nonce then such an application could
  inadvertently encrypt messages with a reused nonce.

  Additionally the ignored bytes in a long nonce are not covered by the integrity
  guarantee of this cipher. Any application that relies on the integrity of these
  ignored leading bytes of a long nonce may be further affected.

  Any OpenSSL internal use of this cipher, including in SSL/TLS, is safe because
  no such use sets such a long nonce value. However user applications that use
  this cipher directly and set a non-default nonce length to be longer than 12
  bytes may be vulnerable.");

  script_tag(name:"affected", value:"OpenSSL versions 1.1.1 up to and including 1.1.1b and
  1.1.0 up to and including 1.1.0j.

  This issue does not impact OpenSSL 1.0.2.");

  script_tag(name:"solution", value:"Upgrade OpenSSL to version 1.1.0k, 1.1.1c or later.
  See the references for more details.");

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

vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"1.1.0", test_version2:"1.1.0j" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.0k", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:vers, test_version:"1.1.1", test_version2:"1.1.1b" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.1c", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );