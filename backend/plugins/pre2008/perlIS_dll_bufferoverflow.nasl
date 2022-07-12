# OpenVAS Vulnerability Test
# $Id: perlIS_dll_bufferoverflow.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: ActivePerl perlIS.dll Buffer Overflow
#
# Authors:
# Drew Hintz ( http://guh.nu )
# It is based on scripts written by Renaud Deraison and  HD Moore
#
# Copyright:
# Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )
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
  script_oid("1.3.6.1.4.1.25623.1.0.10811");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3526);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0815");
  script_name("ActivePerl perlIS.dll Buffer Overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/banner");

  script_tag(name:"solution", value:"Either upgrade to a version of ActivePerl more
  recent than 5.6.1.629 or enable the Check that file exists option.

  To enable this option, open up the IIS MMC, right click on a (virtual) directory in
  your web server, choose Properties, click on the Configuration... button, highlight
  the .plx item, click Edit, and then check Check that file exists.");

  script_tag(name:"summary", value:"An attacker can run arbitrary code on the remote computer.

  This is because the remote IIS server is running a version of ActivePerl prior to 5.6.1.630
  and has the Check that file exists option disabled for the perlIS.dll.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
sig = get_http_banner(port:port);
if( ! sig || "IIS" >!< sig )
  exit(0);

function check(url) {

  req = http_get(item:url, port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if(!r)
    return(0);

  if("HTTP/1.1 500 Server Error" >< r && ("The remote procedure call failed." >< r || "<html><head><title>Error</title>" >< r)) {
    security_message(port:port);
    return(1);
  }
  return(0);
}

foreach dir(make_list("/scripts/", "/cgi-bin/", "/")) {

  url = string(dir, crap(660), ".plx"); #by default perlIS.dll handles .plx
  if(check(req:url))
    exit(0);

  url = string(dir, crap(660), ".pl");
  if(check(req:url))
    exit(0);
}

exit(99);