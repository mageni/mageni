##############################################################################
# OpenVAS Vulnerability Test
#
# SQLiteManager Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800281");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4539");
  script_bugtraq_id(36002);
  script_name("SQLiteManager Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28642");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36002");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sqlitemanager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sqlitemanager/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to disclose sensitive information,
  or conduct cross-site scripting attacks.");

  script_tag(name:"affected", value:"SQLiteManager version 1.2.0 and prior.");

  script_tag(name:"insight", value:"- Input passed to the 'redirect' parameter in 'main.php' is not properly
  sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running SQLiteManager and is prone to Cross Site
  Scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

sqlPort = get_http_port(default:80);

sqliteVer = get_kb_item("www/" + sqlPort + "/SQLiteManager");
if(!sqliteVer)
  exit(0);

sqliteVer = eregmatch(pattern:"^(.+) under (/.*)$", string:sqliteVer);
if(!safe_checks())
{
  url = string(sqliteVer[2], "/main.php?redirect=<script>alert('Exploit-XSS')</script>");
  sndReq = http_get(item:url, port:sqlPort);
  rcvRes = http_send_recv(port:sqlPort, data:sndReq);
  if(rcvRes =~ "^HTTP/1\.[01] 200" && "Exploit-XSS" >< rcvRes) {
    report = report_vuln_url(port:sqlPort, data:report);
    security_message(port:sqlPort, data:report);
    exit(0);
  }
}

if(sqliteVer[1] != NULL)
{
  if(version_is_less_equal(version:sqliteVer[1], test_version:"1.2.0")){
    security_message(sqlPort);
  }
}
