###############################################################################
# OpenVAS Vulnerability Test
#
# Cross-Site Scripting Vulnerability in LightNEasy
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
  script_oid("1.3.6.1.4.1.25623.1.0.900372");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1937");
  script_bugtraq_id(35229);
  script_name("Cross-Site Scripting Vulnerability in LightNEasy");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35354");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/504092/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LightNEasy");
  script_family("Web application abuses");
  script_dependencies("secpod_lightneasy_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lightneasy/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject arbitrary HTML and
  script code, which will be executed when the malicious comment is viewed and
  disclose the content of arbitrary files on an affected system.");

  script_tag(name:"affected", value:"LightNEasy version 2.2.1 and prior (no database) and
  LightNEasy version 2.2.2 and prior (SQLite)");

  script_tag(name:"insight", value:"Multiple flaws arise because,

  - The input passed to the 'commentname', 'commentemail' and 'commentmessage'
  parameters when posting a comment is not properly sanitised before being used.

  - The input passed via the 'page' parameter to LightNEasy.php is not properly
  sanitised before being used to read files and can be exploited by directory
  traversal attacks.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to LightNEasy version 3.1 or later.");

  script_tag(name:"summary", value:"This host is running LightNEasy and is prone to Cross-Site
  Scripting vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

lightNEasyPort = get_http_port(default:80);

sqliteVer = get_kb_item("www/"+ lightNEasyPort + "/LightNEasy/Sqlite");
if(sqliteVer != NULL)
{
  sqliteVer = eregmatch(pattern:"^(.+) under (/.*)$", string:sqliteVer);
  if(sqliteVer[1] != NULL)
  {
    if(version_is_less_equal(version:sqliteVer[1], test_version:"2.2.2")){
      security_message(lightNEasyPort);
      exit(0);
    }
  }
}

nodbVer = get_kb_item("www/"+ lightNEasyPort + "/LightNEasy/NoDB");
if(nodbVer != NULL)
{
  nodbVer = eregmatch(pattern:"^(.+) under (/.*)$", string:nodbVer);
  if(nodbVer[1] != NULL)
  {
    if(version_is_less_equal(version:nodbVer[1], test_version:"2.2.1")){
      security_message(lightNEasyPort);
    }
  }
}
