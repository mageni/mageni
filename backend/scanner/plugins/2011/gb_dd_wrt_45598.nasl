###############################################################################
# OpenVAS Vulnerability Test
#
# DD-WRT '/Info.live.htm' Multiple Information Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103012");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-05 15:07:33 +0100 (Wed, 05 Jan 2011)");
  script_bugtraq_id(45598);

  script_name("DD-WRT '/Info.live.htm' Multiple Information Disclosure Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45598");
  script_xref(name:"URL", value:"http://www.dd-wrt.com/dd-wrtv3/dd-wrt/about.html");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Dec/651");

  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_app");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"DD-WRT is prone to multiple remote information-disclosure issues
  because it fails to restrict access to sensitive information.");

  script_tag(name:"impact", value:"A remote attacker can exploit these issues to obtain sensitive
  information, possibly aiding in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

url = string("/Info.live.htm");

if(http_vuln_check(port:port, url:url, pattern:"\{lan_mac::", extra_check:make_list("\{wan_mac::","\{lan_ip::","\{lan_proto::"), usecache:TRUE)) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);