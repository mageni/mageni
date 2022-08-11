##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_showcase_multiple_xss_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Apache Struts Showcase Multiple Persistence Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802422");
  script_version("$Revision: 13659 $");
  script_bugtraq_id(51902);
  script_cve_id("CVE-2012-1006");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-02-08 12:14:38 +0530 (Wed, 08 Feb 2012)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Struts Showcase Multiple Persistence Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Apache Struts Showcase
  and is prone to multiple persistence cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP POST request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws due to an,

  - Input passed via the 'name' and 'lastName' parameter in
  '/struts2-showcase/person/editPerson.action' is not properly verified
  before it is returned to the user.

  - Input passed via the 'clientName' parameter in
  '/struts2-rest-showcase/orders' action is not properly verified before
  it is returned to the user.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker
  to execute arbitrary HTML code in a user's browser session in the context of a vulnerable
  application.");

  script_tag(name:"affected", value:"Apache struts 1.3.10, 2.0.14 and 2.2.3 and 2.3.1.2");


  script_tag(name:"solution", value:"Upgrade to Apache Struts to version 2.3.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=450");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SecPod_Apache_Struts_Multiple_Parsistant_XSS_Vulns.txt");
  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);

  script_xref(name:"URL", value:"http://struts.apache.org/download.cgi");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!asport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:asport)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:asport);

asreq = http_get(item:string(dir,"/showcase.action"), port:asport);
if(!isnull(asreq))
{
  asres = http_keepalive_send_recv(port:asport, data:asreq);

  if(!isnull(asres))
  {
    if(">Showcase</" >< asres && ">Struts Showcase<" >< asres)
    {
      postdata = "person.name=%3Cscript%3Ealert%28document.cookie%29%3C%2" +
                   "Fscript%3E&person.lastName=%3Cscript%3Ealert%28document" +
                  ".cookie%29%3C%2Fscript%3E";

        asReq = string("POST ", dir, "/person/newPerson.action HTTP/1.1\r\n",
                       "Host: ", host, "\r\n",
                       "User-Agent: ", useragent, "\r\n",
                       "Content-Type: application/x-www-form-urlencoded\r\n",
                       "Content-Length: ", strlen(postdata), "\r\n",
                       "\r\n", postdata);
        asRes = http_keepalive_send_recv(port:asport, data:asReq);

        if(!isnull(asRes))
        {
          asreq = http_get(item:string(dir,"/person/listPeople.action"),
                           port:asport);
          if(!isnull(asreq))
          {
            asresp = http_keepalive_send_recv(port:asport, data:asreq);

            if(asresp =~ "HTTP/1\.. 200" &&
               ("<script>alert(document.cookie)</script>" >< asresp) &&
               ">Struts Showcase<" >< asresp)
            {
              security_message(asport);
              exit(0);
            }
          }
        }
      }
   }
}
