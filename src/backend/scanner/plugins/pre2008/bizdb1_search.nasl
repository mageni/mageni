# OpenVAS Vulnerability Test
# Description: bizdb1-search.cgi located
#
# Authors:
# RWT roelof@sensepost.com 26/4/2000
#
# Copyright:
# Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10383");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1104);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2000-0287");
  script_name("bizdb1-search.cgi located");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Roelof Temmingh <roelof@sensepost.com>");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.hack.co.za/daem0n/cgi/cgi/bizdb.htm");

  script_tag(name:"summary", value:"One of the BizDB scripts, bizdb-search.cgi, passes a variable's
  contents to an unchecked open() call and can therefore be made to execute commands at the privilege
  level of the webserver.");

  script_tag(name:"impact", value:"The variable is dbname, and if passed a semicolon followed by shell
  commands they will be executed. This cannot be exploited from a browser, as the software checks for
  a referrer field in the HTTP request. A valid referrer field can however be created and sent
  programmatically or via a network utility like netcat.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

cgi = string("bizdb1-search.cgi");
res = is_cgi_installed_ka(item:cgi, port:port);
if(res) {
  if(is_cgi_installed_ka(item:"vt-test" + rand() + ".cgi", port:port))
    exit(0);
  security_message(port:port);
  exit(0);
}

exit(99);