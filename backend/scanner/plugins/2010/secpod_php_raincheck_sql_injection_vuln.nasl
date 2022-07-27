###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_raincheck_sql_injection_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# phpRAINCHECK 'print_raincheck.php' SQL injection vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901113");
  script_version("2019-03-21T13:38:28+0000");
  script_cve_id("CVE-2010-1538");
  script_bugtraq_id(38521);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-03-21 13:38:28 +0000 (Thu, 21 Mar 2019)");
  script_tag(name:"creation_date", value:"2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)");
  script_name("phpRAINCHECK 'print_raincheck.php' SQL injection vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/11586");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56578");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1002-exploits/phpraincheck-sql.txt");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary
  SQL queries and gain access to sensitive information.");

  script_tag(name:"affected", value:"PHP RAINCHECK 1.0.1 and prior.");

  script_tag(name:"insight", value:"The flaw is caused by an improper validation of user-supplied input
  via the 'id' parameter in print_raincheck.php that allows an attacker to manipulate SQL
  queries by injecting arbitrary SQL code.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running phpRAINCHECK which is prone to a SQL injection
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir(make_list_unique("/", "/rainchecks", "/phprainchecks", cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/settings.php", port:port);

  if('>phpRAINCHECK - Settings<' >< res) {
    ver = eregmatch(pattern:"Version: ([0-9.]+)", string:res);
    if(ver[1]) {
      if(version_is_less_equal(version:ver[1], test_version:"1.0.1")) {
        report = report_fixed_ver(installed_version:ver[1], fixed_version:"None", install_url:install);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
