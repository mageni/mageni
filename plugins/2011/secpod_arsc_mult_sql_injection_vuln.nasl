###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_arsc_mult_sql_injection_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# A Really Simple Chat Multiple SQL Injection Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902608");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-2181");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("A Really Simple Chat Multiple SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/06/02/7");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/06/02/1");
  script_xref(name:"URL", value:"http://www.htbridge.ch/advisory/multiple_sql_injections_in_a_really_simple_chat_arsc.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to alter queries to
  the SQL database, execute arbitrary queries to the database, compromise the
  application, access or modify sensitive data.");
  script_tag(name:"affected", value:"A Really Simple Chat version 3.3-rc2.");
  script_tag(name:"insight", value:"The flaws are due to improper validation of user supplied data
  to 'arsc_user parameter' in edit_user.php, 'arsc_layout_id' parameter in
  edit_layout.php and 'arsc_room' parameter in edit_room.php, which allows
  attacker to execute arbitrary SQL commands.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running A Really Simple Chat and is prone to multiple
  SQL injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/arsc", "/chat", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:dir + "/base/index.php", port:port);

  if("Powered by ARSC" >< rcvRes && "v3.3-rc2" >< rcvRes)
  {
    security_message(port:port);
    exit(0);
  }
}

exit(99);