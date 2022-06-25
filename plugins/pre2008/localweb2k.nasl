# OpenVAS Vulnerability Test
# $Id: localweb2k.nasl 12821 2018-12-18 12:37:20Z cfischer $
# Description: LocalWeb2000 remote read
#
# Authors:
# Jason Lidow <jason@brandx.net>
#
# Copyright:
# Copyright (C) 2002 Jason Lidow <jason@brandx.net>
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

# The vulnerability was originally discovered by ts@securityoffice.net

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11005");
  script_version("$Revision: 12821 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 13:37:20 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2268, 4820, 7947);
  script_cve_id("CVE-2001-0189");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("LocalWeb2000 remote read");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Jason Lidow <jason@brandx.net>");
  script_family("Remote file access");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("LocalWEB2000/banner");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote host is running LocalWeb2000.

  Version 2.1.0 of LocalWeb2000 allows an attacker to view protected files on the host's computer.

  Example: vulnerableserver.com/./protectedfolder/protectedfile.htm

  It may also disclose the NetBIOS name of the remote host when it receives malformed directory requests.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if(banner && egrep(pattern:"^Server: .*LocalWEB2000.*", string:banner, icase:TRUE)){
  security_message(port:port);
}

exit(0);