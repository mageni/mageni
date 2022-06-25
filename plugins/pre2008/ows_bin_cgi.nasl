# OpenVAS Vulnerability Test
# $Id: ows_bin_cgi.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: ows-bin
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
#	- script id
#	- minor changes in the english description
#
# Copyright:
# Copyright (C) 2000 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.10348");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1053);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-0169");
  script_name("ows-bin");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/Oracle_Web_Listener_4_0_x_CGI_vulnerability.html");

  script_tag(name:"solution", value:"If 'ows-bin' is the default CGI directory used by the Oracle Application Server Manager,
  then remove the ows-bin virtual directory or point it to a more benign directory.

  If 'ows-bin' is not the default then verify that there are no batch files in this directory.");

  script_tag(name:"summary", value:"Oracle's Web Listener (a component of the Oracle Application Server),
  is installed and can be used by a remote attacker to run arbitrary commands on the web server.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = "/ows-bin/perlidlc.bat";
res = is_cgi_installed_ka(item:url, port:port);
if(!res)
  exit(0);

url = "/ows-bin/perlidlc.bat?&dir";
req = http_get(item:url, port:port);
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if("ows-bin:" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);