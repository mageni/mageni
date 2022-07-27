###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_escparameters_dos_vuln_dec15_lin.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL ECParameters Denial of Service Vulnerability Dec15 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.806747");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2015-1788");
  script_bugtraq_id(75158);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-12-01 09:41:47 +0530 (Tue, 01 Dec 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL ECParameters Denial of Service Vulnerability Dec15 (Linux)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error while processing
  ECParameters structure.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service against any system which processes
  public keys, certificate requests or certificates.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2 before 1.0.2b, 1.0.1
  before 1.0.1n, 1.0.0 before 1.0.0e, 0.9.8 before 0.9.8s on Linux");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 0.9.8s or 1.0.0e or
  1.0.1n  or 1.0.2b or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20150611.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities.html");

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

if(vers =~ "^0\.9\.8")
{
  if(version_is_less(version:vers, test_version:"0.9.8s"))
  {
    fix = "0.9.8s";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.0")
{
  if(version_is_less(version:vers, test_version:"1.0.0e"))
  {
    fix = "1.0.0e";
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