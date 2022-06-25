# OpenVAS Vulnerability Test
# $Id: iis5_sample_path.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IIS 5.0 Sample App reveals physical path of web root
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2000 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10573");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("IIS 5.0 Sample App reveals physical path of web root");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Matt Moore");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Always remove sample applications from productions servers.
  In this case, remove the entire /iissamples folder.");

  script_tag(name:"summary", value:"A sample application shipped with IIS 5.0 discloses
  the physical path of the web root. An attacker can use this information
  to make more focused attacks.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) )
  exit(0);

cgi = "/iissamples/sdk/asp/interaction/ServerVariables_Jscript.asp";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res) {
  report = report_vuln_url(port:port, url:cgi);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);