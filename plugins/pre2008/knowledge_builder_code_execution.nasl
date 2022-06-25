# OpenVAS Vulnerability Test
# $Id: knowledge_builder_code_execution.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Remote Code Execution in Knowledge Builder
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.11959");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Remote Code Execution in Knowledge Builder");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version or disable this CGI altogether.");

  script_tag(name:"summary", value:"KnowledgeBuilder is a feature-packed knowledge base solution CGI suite.

  A vulnerability in this product may allow a remote attacker to execute
  arbitrary commands on this host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach path(make_list_unique("/kb", cgi_dirs(port:port))) {

  if(path == "/")
   path = "";

  url = path + "/index.php?page=http://xxxxxxxxxxxxx/vt-test";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  find = string("operation error");
  find_alt = string("getaddrinfo failed");

  if(find >< res || find_alt >< res ) {
    req = http_get(item:path + "/index.php?page=index.php", port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if(!res)
      continue;

    if( find >< res || find_alt >< res )
      continue;

    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);