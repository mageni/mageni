###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_bnwexpand_mul_vuln_win.nasl 13899 2019-02-27 09:14:23Z cfischer $
#
# OpenSSL 'bn_wexpand()' Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800489");
  script_version("$Revision: 13899 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 10:14:23 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3245");
  script_name("OpenSSL 'bn_wexpand()' Multiple Vulnerabilities (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38761");
  script_xref(name:"URL", value:"http://marc.info/?l=openssl-cvs&m=126692159706582&w=2");
  script_xref(name:"URL", value:"http://security-tracker.debian.org/tracker/CVE-2009-3245");
  script_xref(name:"URL", value:"http://www.slproweb.com/products/Win32OpenSSL.html");

  script_tag(name:"impact", value:"Has unspecified impact and context-dependent attack vectors.");

  script_tag(name:"affected", value:"OpenSSL version prior to 0.9.8m on Windows.");

  script_tag(name:"insight", value:"Multiple flaws are due to error in 'bn_wexpand()' function which does not
  check for a NULL return value when called in 'crypto/bn/bn_div.c',
  'crypto/bn/bn_gf2m.c', 'crypto/ec/ec2_smpl.c', and 'engines/e_ubsec.c'.");

  script_tag(name:"solution", value:"Upgrade to version 0.9.8m or later.");

  script_tag(name:"summary", value:"This host is installed with OpenSSL and is prone to multiple
  vulnerabilities.");

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

if( version_is_less( version:vers, test_version:"0.9.8m" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.9.8m", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );