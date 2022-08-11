###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sjs_am_n_opensso_info_disc_vuln.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# Sun JS Access Manager And OpenSSO Information Disclosure vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900818");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2712");
  script_bugtraq_id(35963);
  script_name("Sun JS Access Manager And OpenSSO Information Disclosure vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_sun_opensso_detect.nasl", "secpod_sjs_access_manager_detect.nasl");
  script_mandatory_keys("JavaSysAccessManger_or_OracleOpenSSO/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36169/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2177");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-66-255968-1");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-21-119465-16-1");

  script_tag(name:"impact", value:"Successful exploitation could allow a remote unprivileged user to gain sensitive information.");

  script_tag(name:"affected", value:"Sun OpenSSO Enterprise version 8.0

  Java System Access Manager version 6.3 2005Q1 or 7.0 2005Q4 or 7.1");

  script_tag(name:"insight", value:"Error exists when 'AMConfig.properties' enables the debug flag, allows local
  users to discover cleartext passwords by reading debug files.");

  script_tag(name:"summary", value:"The host is running Access Manager or OpenSSO and is prone to
  an information disclosure vulnerability.");

  script_tag(name:"solution", value:"Apply the security updates from the references.


  *****

  NOTE: Ignore this warning if above mentioned patch is already applied.

  *****");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # nb: The version check below is completely broken...

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

am_port = get_http_port(default:8080);

amVer = get_kb_item("www/" + am_port + "/Sun/JavaSysAccessManger");
amVer = eregmatch(pattern:"^(.+) under (/.*)$", string:amVer);
if(version_is_equal(version:amVer[1], test_version:"7.1") || version_is_equal(version:amVer[1], test_version:"7.0.2005Q4") || version_is_equal(version:amVer[1], test_version:"6.3.2005Q1"))
{
  security_message(port:am_port, data:"The target host was found to be vulnerable.");
  exit(0);
}

ssoVer = get_kb_item("www/" + am_port + "/Sun/OpenSSO");
ssoVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ssoVer);
if(version_is_equal(version:ssoVer[1], test_version:"8.0"))
{
  security_message(port:am_port, data:"The target host was found to be vulnerable.");
  exit(0);
}

exit(99);
