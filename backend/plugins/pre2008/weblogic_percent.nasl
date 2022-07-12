# OpenVAS Vulnerability Test
# $Id: weblogic_percent.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WebLogic Server /%00/ bug
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2001 StrongHoldNet
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10698");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2513);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WebLogic Server /%00/ bug");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 StrongHoldNet");
  script_family("Remote file access");
  script_dependencies("http_version.nasl", "oracle_webLogic_server_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OracleWebLogicServer/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2513");

  script_tag(name:"solution", value:"Upgrade to WebLogic 6.0 with Service Pack 1.");

  script_tag(name:"summary", value:"Requesting a URL with '%00', '%2e', '%2f' or '%5c' appended to it
  makes some WebLogic servers dump the listing of the page directory, thus showing potentially sensitive files.");

  script_tag(name:"impact", value:"An attacker may also use this flaw to view
  the source code of JSP files, or other dynamic content.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

function http_getdirlist(itemstr, port) {

  buffer = http_get(item:itemstr, port:port);
  rbuf = http_keepalive_send_recv(port:port, data:buffer);
  if(!rbuf)
    return;

  data = tolower(rbuf);
  if(("directory listing of" >< data) || ("index of" >< data)) {
    if(strlen(itemstr) > 1) {
      report = report_vuln_url(port:port, url:itemstr);
      security_message(port:port, data:report);
    } else if(strlen(itemstr) == 1) { # If itemstr = / we exit the test to avoid FP.
      exit(0);
    }
  }
}

port = get_http_port(default:80);

if(!get_kb_item("www/" + port + "/WebLogic_Server"))
  exit(0); # make sure it is a WebLogic Server at this port.

http_getdirlist(itemstr:"/", port:port); # Anti FP
http_getdirlist(itemstr:"/%2e/", port:port);
http_getdirlist(itemstr:"/%2f/", port:port);
http_getdirlist(itemstr:"/%5c/", port:port);
http_getdirlist(itemstr:"/%00/", port:port);