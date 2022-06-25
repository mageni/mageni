###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_info_disc_vuln_sep18_win.nasl 13898 2019-02-27 08:37:43Z cfischer $
#
# OpenSSL: Information Disclosure Vulnerability (CVE-2016-7056) (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813793");
  script_version("$Revision: 13898 $");
  script_cve_id("CVE-2016-7056");
  script_bugtraq_id(95375);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 09:37:43 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-09-11 11:49:25 +0530 (Tue, 11 Sep 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL: Information Disclosure Vulnerability (CVE-2016-7056) (Windows)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient setting
  in the 'BN_FLG_CONSTTIME' flag for nonces, which could trigger a failure to take
  a secure code path in the BN_mod_inverse method that results in a cache-timing
  condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow a malicious
  user with local access to recover ECDSA P-256 private keys.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.1u and prior.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0 or 1.0.2
  or later. See the references for more details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=52295");
  script_xref(name:"URL", value:"https://eprint.iacr.org/2016/1195");
  script_xref(name:"URL", value:"https://git.openssl.org/?p=openssl.git;a=commit;h=8aed2a7548362e88e84a7feb795a3a97e8395008");
  script_xref(name:"URL", value:"https://www.openssl.org");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(sslPort = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location( cpe:CPE, port:sslPort, exit_no_version:TRUE))
 exit(0);

sslVer = infos['version'];
sslPath = infos['location'];

if(version_is_less_equal(version:sslVer, test_version:"1.0.1u")){
  report = report_fixed_ver(installed_version:sslVer, fixed_version:"1.1.0 or 1.0.2", install_path:sslPath);
  security_message(data:report, port:sslPort);
  exit(0);
}

exit(99);