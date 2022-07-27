###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_sec_bypass_vuln_win.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL Security Bypass Vulnerability - DEC 2017 (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107268");
  script_version("$Revision: 13898 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-12-08 12:22:37 +0100 (Fri, 08 Dec 2017)");
  script_cve_id("CVE-2017-3737");
  script_bugtraq_id(102103);

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL Security Bypass Vulnerability - DEC 2017 (Windows)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to a security bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Get the installed version and check if it is vulnerable.");

  script_tag(name:"insight", value:"When SSL_read()/SSL_write() is subsequently called by the
  application for the same SSL object then it will succeed and the data is passed without being
  decrypted/encrypted directly from the SSL/TLS record layer.");

  script_tag(name:"impact", value:"Successfully exploiting this issue would allow an attacker to cause a denial of service.");

  script_tag(name:"affected", value:"OpenSSL 1.0.2: from 1.0.2b to 1.0.2m");
  script_tag(name:"solution", value:"OpenSSL 1.0.2 users should upgrade to 1.0.2n.");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20171207.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102103");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if (vers =~ "^(1\.0\.2)")
{
  if(version_in_range(version:vers, test_version:"1.0.2b", test_version2:"1.0.2m"))
  {
    report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2n", install_path:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);