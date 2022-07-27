###############################################################################
# OpenVAS Vulnerability Test
# $Id: proftpd_36804.nasl 13602 2019-02-12 12:47:59Z cfischer $
#
# ProFTPD mod_tls Module NULL Character CA SSL Certificate Validation Security Bypass Vulnerability
#
# Authors:
# Michael Meyer
#
# Updated to check ProFTPD version 1.3.3 before 1.3.3.rc2
#   - By Antu Sanadi <santu@secpod.com> On 2009/11/02
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:proftpd:proftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100316");
  script_version("$Revision: 13602 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-12 13:47:59 +0100 (Tue, 12 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-10-26 10:02:32 +0100 (Mon, 26 Oct 2009)");
  script_bugtraq_id(36804);
  script_cve_id("CVE-2009-3639");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("ProFTPD mod_tls Module NULL Character CA SSL Certificate Validation Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("secpod_proftpd_server_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ProFTPD/Installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36804");
  script_xref(name:"URL", value:"http://bugs.proftpd.org/show_bug.cgi?id=3275");
  script_xref(name:"URL", value:"http://www.proftpd.org");

  script_tag(name:"summary", value:"ProFTPD is prone to a security-bypass vulnerability because the
  application fails to properly validate the domain name in a signed CA
  certificate, allowing attackers to substitute malicious SSL
  certificates for trusted ones.");
  script_tag(name:"affected", value:"Versions prior to ProFTPD 1.3.2b and 1.3.3 to 1.3.3.rc1 are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"impact", value:"Successful exploits allows attackers to perform man-in-the-
  middle attacks or impersonate trusted servers, which will aid in further attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.3.2.b" ) ||
    version_in_range( version:vers, test_version:"1.3.3", test_version2:"1.3.3.rc1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.2b/1.3.3rc2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );