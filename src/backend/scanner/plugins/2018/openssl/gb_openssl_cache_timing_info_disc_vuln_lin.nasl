###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_cache_timing_info_disc_vuln_lin.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL: 1.0.2 < 1.0.2p / 1.1.0 < 1.1.0i Multiple Vulnerabilities (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813154");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2018-0732", "CVE-2018-0737");
  script_bugtraq_id(103766, 104442);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-04-23 18:50:10 +0530 (Mon, 23 Apr 2018)");
  script_name("OpenSSL: 1.0.2 < 1.0.2p / 1.1.0 < 1.1.0i Multiple Vulnerabilities (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20180416.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20180612.txt");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q2/50");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/ea7abeeabf92b7aca160bdd0208636d4da69f4f4");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/3984ef0b72831da8b3ece4745cac4f8575b19098");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/6939eab03a6e23d2bd2c3f5e34fe1d48e542e787");
  script_xref(name:"URL", value:"https://github.com/openssl/openssl/commit/349a41da1ad88ad87825414752a8ff5fdd6a6c3f");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to:

  - During key agreement in a TLS handshake using a DH(E) based ciphersuite a malicious server can send
  a very large prime value to the client (CVE-2018-0732).

  - The OpenSSL RSA Key generation algorithm has been shown to be vulnerable to a cache timing side channel
  attack (CVE-2018-0737).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker:

  - to cause the client to spend an unreasonably long period of time generating a key for this prime resulting
  in a hang until the client has finished. This could be exploited in a Denial Of Service attack (CVE-2018-0732).

  - with sufficient access to mount cache timing attacks during the RSA key generation process could recover the
  private key (CVE-2018-0737).");

  script_tag(name:"affected", value:"OpenSSL 1.1.0-1.1.0h and 1.0.2-1.0.2o.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0i or 1.0.2p or
  later. See the references for more details.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if( version_in_range( version:vers, test_version:"1.0.2", test_version2:"1.0.2o" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.2p", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );