# OpenVAS Vulnerability Test
# $Id: weblogic_adm_servlet.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WebLogic management servlet
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Thanks to Sullo who supplied a sample of WebLogic banners
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11486");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1095");
  script_bugtraq_id(7122, 7124, 7130, 7131);
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WebLogic management servlet");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/weblogic");

  script_xref(name:"URL", value:"http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-28.jsp");

  script_tag(name:"summary", value:"The remote web server is WebLogic.

  An internal management servlet which does not properly check user credential can be accessed from outside, allowing
  an attacker to change user passwords, and even upload or download any file on the remote server.

  In addition to this, there is a flaw in WebLogic 7.0 which may allow users to delete empty subcontexts.");

  script_tag(name:"solution", value:"- Apply Service Pack 2 Rolling Patch 3 on WebLogic 6.0

  - Apply Service Pack 4 on WebLogic 6.1

  - Apply Service Pack 2 on WebLogic 7.0 or 7.0.0.1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if(!banner || "WebLogic " >!< banner)
  exit(0); # Not WebLogic

# All those tests below have NEVER been validated!
# Here are the banner we got:
# WebLogic 5.1.0 04/03/2000 17:13:23 #66825
# WebLogic 5.1.0 Service Pack 10 07/11/2001 21:04:48 #126882
# WebLogic 5.1.0 Service Pack 12 04/14/2002 22:57:48 #178459
# WebLogic 5.1.0 Service Pack 6 09/20/2000 21:03:19 #84511
# WebLogic 5.1.0 Service Pack 9 04/06/2001 12:48:33 #105983 - 128 bit domestic version
# WebLogic WebLogic Server 6.1 SP1  09/18/2001 14:28:44 #138716
# WebLogic WebLogic Server 6.1 SP3  06/19/2002 22:25:39 #190835
# WebLogic WebLogic Temporary Patch for CR067505 02/12/2002 17:10:21

# I suppose that this kind of thing might exist
if(" Temporary Patch for CR096950" >< banner)
  exit(0);

if(banner =~ "WebLogic .* 6\.1 ") {
  if(" SP4 " >!< banner)
    security_message(port:port);
  exit(0);
}

if(banner =~ "WebLogic .* 6\.0 ") {
  if(banner !~ " SP[3-9] " && " SP2 RP3 " >!< banner)
    security_message(port:port);
  exit(0);
}

if(banner =~ "WebLogic .* 7\.0(\.0\.1)? ") {
  if(banner !~ " SP[2-9]")
    security_message(port:port);
  exit(0);
}

exit(99);