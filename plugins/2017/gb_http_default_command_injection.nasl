###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_default_command_injection.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Generic HTTP Command Injection Check
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112054");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-09-27 09:42:21 +0200 (Wed, 27 Sep 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Generic HTTP Command Injection Check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/Code_Injection");

  script_tag(name:"summary", value:"The script checks for generic code vulnerabilities in web pages.

  NOTE: Please enable 'Enable generic web application scanning' within the NVT 'Global variable settings'
  (OID: 1.3.6.1.4.1.25623.1.0.12288) if you want to run this script.");

  script_tag(name:"vuldetect", value:"Tries to inject commands into the machine via GET parameter. If successful,
  the vulnerability is confirmed.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary commands
  on the host machine.");

  script_tag(name:"solution", value:"Please contact the specific vendor for a solution.");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

# nb: We also don't want to run if optimize_test is set to "no"
if( http_is_cgi_scan_disabled() ||
    get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

port = get_http_port(default:80);
host = http_host_name(dont_add_port:TRUE);

cgis = http_get_kb_cgis(port:port, host:host);
if(!cgis) exit(0);

cmds = exploit_commands();

foreach cmd (keys(cmds)) {
  # feel free to complement this list with useful and/or necessary expressions
  expressions = make_list("system('" + cmds[cmd] + "')",
                            ";" + cmds[cmd]);
  foreach cgi (cgis) {
    cgiArray = split(cgi, sep:" ", keep:FALSE);
    foreach ex (expressions) {
      urls = http_create_exploit_req(cgiArray:cgiArray, ex:ex);
      foreach url (urls) {
        if(http_vuln_check(port:port, url:url, pattern:cmd)) {
          report = report_vuln_url(port:port, url:url);
          security_message(port:port, data:report);
          exit(0);
        }
      }
    }
  }
}
exit(99);
