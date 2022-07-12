# OpenVAS Vulnerability Test
# Description: IIS 5.0 Sample App vulnerable to cross-site scripting attack
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
  script_oid("1.3.6.1.4.1.25623.1.0.10572");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("IIS 5.0 Sample App vulnerable to cross-site scripting attack");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2000-02.html");

  script_tag(name:"solution", value:"Always remove sample applications from productions servers.

  In this case, remove the entire /iissamples folder.");

  script_tag(name:"summary", value:"The script /iissamples/sdk/asp/interaction/Form_JScript.asp
  (or Form_VBScript.asp) allows you to insert information into a form
  field and once submitted re-displays the page, printing the text you entered.

  This .asp doesn't perform any input validation, and hence you can input a
  string like:

  <SCRIPT>alert(document.domain)</SCRIPT>.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port))
  exit(0);

url = "/iissamples/sdk/asp/interaction/Form_JScript.asp";
if(is_cgi_installed_ka(item:url, port:port)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);