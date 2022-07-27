##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dotproject_mult_xss_n_sql_inj_vuln_900116.nasl 13238 2019-01-23 11:14:26Z cfischer $
# Description: dotProject Multiple XSS and SQL Injection Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900116");
  script_version("$Revision: 13238 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 12:14:26 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2008-09-02 16:25:07 +0200 (Tue, 02 Sep 2008)");
  script_cve_id("CVE-2008-3886");
  script_bugtraq_id(30924);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("dotProject Multiple XSS and SQL Injection Vulnerabilities");
  script_category(ACT_MIXED_ATTACK); # unknown why safe_checks was used below
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"affected", value:"dotProject version 2.1.2 and prior on all platform.");

  script_tag(name:"summary", value:"The host is running dotProject, which is prone to multiple Cross
  Site Scripting and SQL injection vulnerabilities.");

  script_tag(name:"insight", value:"The flaws exist due to,

  - improper sanitisation of input value passed to inactive, date,
  calendar, callback and day_view, public, dialog and ticketsmith
  parameters in index.php before being returned to the user.

  - failing to validate the input passed to the tab and user_id parameter
  in index.php file, before being used in SQL queries.");

  script_tag(name:"solution", value:"Upgrade to dotProject version 2.1.3 or later.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to steal cookie
  based authentication credentials of user and administrator, and can also execute arbitrary code
  in the browser of an unsuspecting user in the context of an affected site.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31681/");
  script_xref(name:"URL", value:"http://packetstorm.linuxsecurity.com/0808-exploits/dotproject-sqlxss.txt");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach path (make_list_unique("/xampp/dotproject_2_1_2/dotproject", cgi_dirs(port:port))) {

  if(path == "/")
    path = "";

  rcvRes = http_get_cache(item: path + "/index.php", port:port);
  if(!rcvRes)
    continue;

  if(rcvRes =~ "^HTTP/1\.[01] 200" && egrep(pattern:"dotProject", string:rcvRes, icase:FALSE)) {
    if(safe_checks()) {
      if(ver = egrep(pattern:"Version ([01]\..*|2\.(0(\..*)?|1(\.[0-2])?))[^.0-9]", string:rcvRes)){
        report = report_fixed_ver(installed_version:ver, fixed_version:"2.1.3");
        security_message(port:port, data:report);
      }
      exit(0);
    }

    url = string(path, "/index.php?m=public&a=calendar&dialog=1&callback=setCalendar%22%3E%3Cimg/src/onerror=alert(101010)%3E");
    sndReq = http_get(item:url, port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);
    if(!rcvRes)
      exit(0);

    if('alert(101010)%3E' >< rcvRes){
      report = report_vuln_url(url:url, port:port);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);