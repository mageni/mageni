###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_n_gnutls_ssl_spoof_vuln_win.nasl 13901 2019-02-27 09:33:17Z cfischer $
#
# OpenSSL/GnuTLS SSL Server Spoofing Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800917");
  script_version("$Revision: 13901 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 10:33:17 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-05 14:14:14 +0200 (Wed, 05 Aug 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2409");
  script_name("OpenSSL/GnuTLS SSL Server Spoofing Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_win.nasl", "gb_gnutls_detect_win.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl_or_gnutls/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2009-2409");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker spoof the SSL cerficate and gain
  unauthorized access.");

  script_tag(name:"affected", value:"OpenSSL version 0.9.8 through 0.9.8k
  GnuTLS version before 2.6.4 and before 2.7.4 on Windows");

  script_tag(name:"insight", value:"The NSS library used in these applications support MD2 with X.509
  certificates, which allows certificate to be spoofed using MD2 hash collision design flaws.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 1.0.0 or later and GnuTLS 2.6.4 or 2.7.4 or later.");

  script_tag(name:"summary", value:"This host is running OpenSSL/GnuTLS and is prone to SSL server
  spoofing vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list( "cpe:/a:openssl:openssl", "cpe:/a:gnu:gnutls" );

if( isnull( infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! infos = get_app_version_and_location( cpe:cpe, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( "openssl" >< cpe ) {
  if( version_in_range( version:vers, test_version:"0.9.8", test_version2:"0.9.8k" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"1.0.0", install_path:path );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
} else if( "gnutls" >< cpe ) {
  if( version_in_range( version:vers, test_version:"2.6.0", test_version2:"2.6.3" ) ||
      version_in_range( version:vers, test_version:"2.7.0", test_version2:"2.7.3" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"2.6.4/2.7.4", install_path:path );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit( 0 );