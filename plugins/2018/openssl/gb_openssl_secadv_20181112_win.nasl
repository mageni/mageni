###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_secadv_20181112_win.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL: Microarchitecture timing vulnerability in ECC scalar multiplication (CVE-2018-5407) (Windows)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108484");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2018-5407");
  script_bugtraq_id(105897);
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-11-22 07:48:19 +0100 (Thu, 22 Nov 2018)");
  script_name("OpenSSL: Microarchitecture timing vulnerability in ECC scalar multiplication (CVE-2018-5407) (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20181112.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/aab7c770353b1dc4ba045938c8fb446dd1c4531e");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/b18162a7c9bbfb57112459a4d6631fa258fd8c0cq");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105897");
  script_xref(name:"URL", value:"https://eprint.iacr.org/2018/1060.pdf");
  script_xref(name:"URL", value:"https://github.com/bbbrumley/portsmash");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45785/");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"OpenSSL ECC scalar multiplication, used in e.g. ECDSA and ECDH,
  has been shown to be vulnerable to a microarchitecture timing side channel attack.");

  script_tag(name:"impact", value:"An attacker with sufficient access to mount local timing attacks
  during ECDSA signature generation could recover the private key.");

  script_tag(name:"affected", value:"OpenSSL versions 1.1.0-1.1.0h and 1.0.2-1.0.2p.");

  script_tag(name:"solution", value:"Upgrade OpenSSL to version 1.0.2q, 1.1.0i or later. See the references for more details.");

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

if( version_in_range( version:vers, test_version:"1.1.0", test_version2:"1.1.0h" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.0i", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:vers, test_version:"1.0.2", test_version2:"1.0.2p" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.2q", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );