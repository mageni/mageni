##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_posh_mult_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# POSH Multiple Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804244");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-2211", "CVE-2014-2212", "CVE-2014-2213", "CVE-2014-2214");
  script_bugtraq_id(65817, 65818, 65840, 65843);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-03-10 15:56:43 +0530 (Mon, 10 Mar 2014)");
  script_name("POSH Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with POSH and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether it is
  able to read the cookie or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input passed via the 'rssurl' parameter to 'addtoapplication.php'
  and 'error' parameter to 'login.php', which is not properly sanitised
  before using it.

  - It stores the username and md5 digest of the password in the cookie.

  - Improper validation of the 'redirect' parameter upon submission to the
  /posh/portal/scr_sendmd5.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal the victim's
  cookie-based authentication credentials, execute SQL commands and obtain
  sensitive information.");

  script_tag(name:"affected", value:"POSH version before 3.3.0");

  script_tag(name:"solution", value:"Upgrade to version POSH version 3.3.0 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56988");
  script_xref(name:"URL", value:"http://www.sysdream.com/CVE-2014-2211_2214");
  script_xref(name:"URL", value:"http://www.sysdream.com/system/files/POSH-3.2.1-advisory_0.pdf");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://sourceforge.net/projects/posh");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

poshPort = get_http_port(default:80);
if(!can_host_php(port:poshPort)){
  exit(0);
}

foreach dir (make_list_unique("/posh", "/portal", "/", cgi_dirs(port:poshPort)))
{

  if(dir == "/") dir = "";

  poshRes = http_get_cache(item:dir + "/login.php", port:poshPort);

  if(">Login<" >< poshRes && "Email :" >< poshRes && "Password :" >< poshRes &&
     "Memorise" >< poshRes)
  {
    url = dir + "/includes/plugins/mobile/scripts/login.php?" +
          "error=<script>alert(document.cookie)</script>";

    if(http_vuln_check(port: poshPort, url: url, check_header:TRUE,
       pattern: "<script>alert\(document\.cookie\)</script>"))
    {
      security_message(port:poshPort);
      exit(0);
    }
  }
}

exit(99);
