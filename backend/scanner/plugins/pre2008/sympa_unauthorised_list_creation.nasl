# OpenVAS Vulnerability Test
# $Id: sympa_unauthorised_list_creation.nasl 7273 2017-09-26 11:17:25Z cfischer $
# Description: Sympa unauthorised list creation security issue
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14300");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(10941);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_name("Sympa unauthorised list creation security issue");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Update to version 4.1.2 or newer.");

  script_tag(name:"summary", value:"The version of Sympa has an authentication flaw within the web interface.");

  script_tag(name:"impact", value:"An attacker, exploiting this flaw, would be able to bypass security
  mechanisms resulting in the ability to perform listmaster functions remotely.");

  script_xref(name:"URL", value:"http://www.sympa.org/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/wws", "/wwsympa", cgi_dirs(port:port))) {

  if(dir == "/")
    dir = "";

  r = http_get_cache(item:string(dir, "/home"), port:port);
  if(!r)
    continue;

  #TD NOWRAP><I>Powered by</I></TD>
  #<TD><A HREF="http://www.sympa.org/">
  #       <IMG SRC="/icons/sympa/logo-s.png" ALT="Sympa 4.1.2" BORDER="0" >
  if("http://www.sympa.org/" >< r && egrep(pattern:".*ALT=.Sympa (2\.|3\.|4\.0|4\.1\.[01])", string:r)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);