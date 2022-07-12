###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mult_vuln01_nov15_lin.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL Multiple Vulnerabilities -01 Nov15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806729");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2015-1787", "CVE-2015-0290", "CVE-2015-0291", "CVE-2015-0285",
                "CVE-2015-0208", "CVE-2015-0207");
  script_bugtraq_id(73238, 73226, 73235, 73234, 73229);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-11-24 18:49:30 +0530 (Tue, 24 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Multiple Vulnerabilities -01 Nov15 (Linux)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Error in 'sigalgs' implementation in 't1_lib.c' script.

  - multi-block feature in the 'ssl3_write_bytes' function in 's3_pkt.c' script
    does not properly handle certain non-blocking I/O cases.

  - Error in 'sl3_get_client_key_exchange' function in 's3_srvr.c' script.

  - 'ssl3_client_hello' function in 's3_clnt.c' script does not ensure that the
    PRNG is seeded before proceeding with a handshake.

  - Error in ASN.1 signature-verification implementation in the 'rsa_item_verify'
    function in 'crypto/rsa/rsa_ameth.c' script.

  - Imprper handling of state information by 'dtls1_listen' function in
    'd1_lib.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow an remote
  attackers to conduct brute-force attack, to cause a denial of service.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2 before 1.0.2a on
  Linux");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 1.0.2a or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1031929");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20150319.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(vers =~ "^1\.0\.2" && version_is_less(version:vers, test_version:"1.0.2a")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2a", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);