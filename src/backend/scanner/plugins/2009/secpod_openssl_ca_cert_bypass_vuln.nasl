###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openssl_ca_cert_bypass_vuln.nasl 13899 2019-02-27 09:14:23Z cfischer $
#
# OpenSSL CA Certificate Security Bypass Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900464");
  script_version("$Revision: 13899 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 10:14:23 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-03-02 16:07:07 +0100 (Mon, 02 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0653");
  script_name("OpenSSL CA Certificate Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker spoof the SSL cerficate and
  gain sensitive information of the remote user through inserting a malicious
  URL in the contenxt of the openssl certificate.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.6 or prior.");

  script_tag(name:"insight", value:"OpenSSL fails to verify the Basic Constraints for an intermediate CA-signed
  certificate.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.0.0 or later.");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone to Security Bypass
  Vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
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

if( version_is_less_equal( version:vers, test_version:"0.9.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.0", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );