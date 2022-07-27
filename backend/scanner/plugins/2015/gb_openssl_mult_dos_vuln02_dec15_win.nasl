###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mult_dos_vuln02_dec15_win.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL Multiple Denial of Service Vulnerabilities -02 Dec15 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806744");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792");
  script_bugtraq_id(75156, 75157, 75161, 75154);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-12-01 09:41:47 +0530 (Tue, 01 Dec 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL Multiple Denial of Service Vulnerabilities -02 Dec15 (Windows)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An out-of-bounds read vulnerability in 'X509_cmp_time' function in
    'crypto/x509/x509_vfy.c' script.

  - NULL pointer dereference vulnerability in 'PKCS7_dataDecodefunction' in
    'crypto/pkcs7/pk7_doit.c' script.

  - 'ssl3_get_new_session_ticket' function in 'ssl/s3_clnt.c' script causes
    race condition while handling NewSessionTicket.

  - 'do_free_upto' function in 'crypto/cms/cms_smime.c' script verify infinite
    loop with unknown hash function.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"OpenSSL versions before 0.9.8zg, 1.0.0
  before 1.0.0s, 1.0.1 before 1.0.1n, and 1.0.2 before 1.0.2b on Windows");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 0.9.8zg, or 1.0.0s or
  1.0.1n or 1.0.2b or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20150611.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

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

if(vers =~ "^0\.9\.8")
{
  if(version_is_less(version:vers, test_version:"0.9.8zg"))
  {
    fix = "0.9.8zg";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.0")
{
  if(version_is_less(version:vers, test_version:"1.0.0s"))
  {
    fix = "1.0.0s";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.1")
{
  if(version_is_less(version:vers, test_version:"1.0.1n"))
  {
    fix = "1.0.1n";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.2")
{
  if(version_is_less(version:vers, test_version:"1.0.2b"))
  {
    fix = "1.0.2b";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);