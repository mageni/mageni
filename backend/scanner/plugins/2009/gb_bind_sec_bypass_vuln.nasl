###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bind_sec_bypass_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# OpenSSL DSA_verify() Security Bypass Vulnerability in BIND
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800338");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5077", "CVE-2009-0025", "CVE-2009-0265");
  script_bugtraq_id(33150, 33151);
  script_name("OpenSSL DSA_verify() Security Bypass Vulnerability in BIND");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("bind_version.nasl");
  script_mandatory_keys("ISC BIND/installed");

  script_xref(name:"URL", value:"https://www.isc.org/node/373");
  script_xref(name:"URL", value:"http://secunia.com/advisories/33404/");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2008-016.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass the certificate
  validation checks and can cause man-in-the-middle attack via signature checks
  on DSA and ECDSA keys used with SSL/TLS.");

  script_tag(name:"affected", value:"ISC BIND version prior to 9.2 or 9.6.0 P1 or 9.5.1 P1 or 9.4.3 P1 or 9.3.6 P1/Linux.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of return value from OpenSSL's
  DSA_do_verify and VP_VerifyFinal functions.");

  script_tag(name:"solution", value:"Upgrade to version 9.6.0 P1, 9.5.1 P1, 9.4.3 P1, 9.3.6 P1.");

  script_tag(name:"summary", value:"The host is running BIND and is prone to Security Bypass
  Vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

version = eregmatch( pattern:"([0-9.]+)[-| ]?([a-zA-Z0-9]+)?", string:version );
if( version[1] != NULL ) {

  if( version[2] =~ "[a-zA-Z0-9]+" ) {
    version = version[1] + "." + version[2];
  } else {
    version = version[1];
  }

  if( version_in_range( version:version, test_version:"9.6", test_version2:"9.6.0" ) ||
     version_in_range( version:version, test_version:"9.5", test_version2:"9.5.1" ) ||
     version_in_range( version:version, test_version:"9.4", test_version2:"9.4.3" ) ||
     version_in_range( version:version, test_version:"9.3", test_version2:"9.3.6" ) ||
     version_is_less( version:version, test_version:"9.2" ) ){
    report = report_fixed_ver( installed_version:version, fixed_version:"9.6.0 P1, 9.5.1 P1, 9.4.3 P1 or 9.3.6 P1" );
    security_message( data:report, port:port, proto:proto );
    exit( 0 );
  }
}

exit( 99 );