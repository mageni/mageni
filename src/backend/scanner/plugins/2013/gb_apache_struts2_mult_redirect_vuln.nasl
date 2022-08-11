###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts2_mult_redirect_vuln.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Apache Struts2 Redirection and Security Bypass Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803838");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-2248", "CVE-2013-2251");
  script_bugtraq_id(61196, 61189);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-07-24 11:58:54 +0530 (Wed, 24 Jul 2013)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Struts2 Redirection and Security Bypass Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Apache Struts2 and is prone
  to redirection and security bypass vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send an expression along with the redirect command
  via HTTP GET request and check whether it is redirecting and solve the expression or not.");

  script_tag(name:"insight", value:"Flaws are due to improper sanitation of 'action:',
  'redirect:', and 'redirectAction:' prefixing parameters before being used in
  DefaultActionMapper.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker
  to execute arbitrary arbitrary Java code via OGNL (Object-Graph Navigation Language)
  or redirect user to a malicious url.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 to 2.3.15");

  script_tag(name:"solution", value:"Upgrade to Apache Struts 2 version 2.3.15.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54118");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2013/Jul/157");
  script_xref(name:"URL", value:"http://struts.apache.org/development/2.x/docs/s2-016.html");
  script_xref(name:"URL", value:"http://struts.apache.org/development/2.x/docs/s2-017.html");
  script_xref(name:"URL", value:"http://struts.apache.org/release/2.3.x/docs/version-notes-23151.html");
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

asreq = http_get(item:string(dir,"/showcase.action"), port:asport);
asres = http_keepalive_send_recv(port:asport, data:asreq);

if(asres && ">Struts2 Showcase<" >< asres && ">Welcome!<" >< asres)
{
  calc = make_list(2, 3);

  foreach i (calc)
  {
    url = dir + "/showcase.action?redirect%3A%25%7B"+ i +"*5%7D";

    req = http_get(item:url, port:asport);
    res = http_keepalive_send_recv(port:asport, data:req);

    if(res =~ "HTTP/1.. 302" && res =~ "Location:.*/([0-9]+)?")
    {
      result = eregmatch(pattern: string(dir, "/([0-9]+)?"), string:res);

      if ( !result || result[1] >!< i * 5 ) exit(0);
    }
   else exit(0);
  }
  security_message(port:asport);
  exit(0);
}