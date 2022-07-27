###############################################################################
# OpenVAS Vulnerability Test
# $Id: sun_dir_server_37899.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Sun Java System Directory Server LDAP Search Request Denial of Service Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100510");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-26 12:01:21 +0100 (Fri, 26 Feb 2010)");
  script_bugtraq_id(37899);
  script_cve_id("CVE-2010-0708");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Sun Java System Directory Server LDAP Search Request Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("sun_dir_server_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("SunJavaDirServer/installed", "ldap/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37899");
  script_xref(name:"URL", value:"http://www.sun.com/software/products/directory_srvr/home_directory.xml");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-275711-1");

  script_tag(name:"summary", value:"Sun Java System Directory Server is prone to a denial-of-service
  vulnerability.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the effected application,
  denying service to legitimate users.");
  script_tag(name:"affected", value:"- Sun Directory Server Enterprise Edition 7.0

  - Sun Java System Directory Server Enterprise Edition 6.3.1

  - Sun Java System Directory Server Enterprise Edition 6.3

  - Sun Java System Directory Server Enterprise Edition 6.2

  - Sun Java System Directory Server Enterprise Edition 6.1

  - Sun Java System Directory Server Enterprise Edition 6.0

  - Sun Java System Directory Server 5.2");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("ldap.inc");

port = get_ldap_port( default:389 );

if(!version = get_kb_item(string("ldap/",port,"/SunJavaDirServer")))exit(0);

if(!isnull(version)) {
  if(version_is_equal(version: version, test_version: "7.0") ||
     version_in_range(version: version, test_version: "6", test_version2: "6.3.1") ||
     version_is_equal(version: version, test_version: "5.2")) {
       security_message(port:port);
       exit(0);
  }
}

exit(99);
