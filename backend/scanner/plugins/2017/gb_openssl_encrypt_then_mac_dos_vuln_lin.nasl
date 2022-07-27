###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_encrypt_then_mac_dos_vuln_lin.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL Encrypt-Then-Mac Extension Denial of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810702");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2017-3733");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-02-21 15:59:18 +0530 (Tue, 21 Feb 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Encrypt-Then-Mac Extension Denial of Service Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists, during a renegotiation
  handshake if the Encrypt-Then-Mac extension is negotiated where it was not in
  the original handshake (or vice-versa) then this can cause OpenSSL to crash
  (dependent on ciphersuite).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial-of-service condition.");

  ## At the moment not sure about other version affected.
  script_tag(name:"affected", value:"OpenSSL version 1.1.0 on Linux.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0e or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20170216.txt");
  script_xref(name:"URL", value:"http://securityaffairs.co/wordpress/56343/security/openssl-cve-2017-3733.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

if(vers == "1.1.0")
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0e", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);