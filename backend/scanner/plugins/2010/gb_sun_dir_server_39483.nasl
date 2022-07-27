###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_dir_server_39483.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# Oracle Java System Directory Server CVE-2010-0897 Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100577");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-15 19:15:10 +0200 (Thu, 15 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(39453);
  script_cve_id("CVE-2010-0897");
  script_name("Oracle Java System Directory Server Multiple Remote Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("sun_dir_server_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("SunJavaDirServer/installed", "ldap/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39453");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-073/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-074/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-075/");
  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuapr2010.html");

  script_tag(name:"solution", value:"Vendor updates are available. Please contact the vendor for more
  information.");
  script_tag(name:"summary", value:"Oracle Java System Directory Server is prone to multiple remote
  vulnerabilities.");
  script_tag(name:"impact", value:"These vulnerabilities can be exploited over the 'LDAP' and 'HTTP'
  protocols. Remote attackers can exploit these issues without
  authenticating.

  Successful exploits will allow attackers to exploit arbitrary code in
  the context of the vulnerable application or cause denial-of-service
  conditions.");
  script_tag(name:"affected", value:"These vulnerabilities affect the following supported versions:
  5.2, 6.0, 6.1, 6.2, 6.3, 6.3.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("ldap.inc");

port = get_ldap_port( default:389 );

if(!version = get_kb_item(string("ldap/",port,"/SunJavaDirServer")))exit(0);

if(!isnull(version)) {
  if(version_in_range(version: version, test_version: "6", test_version2: "6.3.1") ||
     version_is_equal(version: version, test_version: "5.2")) {
       security_message(port: port);
       exit(0);
  }
}

exit(99);
