###############################################################################
# OpenVAS Vulnerability Test
# $Id: iis_dot_cnf.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Check for IIS .cnf file leakage
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2003 John Lampe....j_lampe@bellsouth.net
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10575");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2002-1717");
  script_bugtraq_id(4078);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Check for IIS .cnf file leakage");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2003 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("IIS/banner");

  script_xref(name:"URL", value:"http://www.safehack.com/Advisory/IIS5webdir.txt");

  script_tag(name:"solution", value:"If you do not need .cnf files, then delete them, otherwise use
  suitable access control lists to ensure that the .cnf files are not world-readable by Anonymous users.");

  script_tag(name:"summary", value:"The IIS web server may allow remote users to read sensitive information
  from .cnf files. This is not the default configuration.

  Example, http://example.com/_vti_pvt%5csvcacl.cnf, access.cnf,
  svcacl.cnf, writeto.cnf, service.cnf, botinfs.cnf,
  bots.cnf, linkinfo.cnf and services.cnf");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig ) exit(0);

host = http_host_name(dont_add_port:TRUE);
if(http_get_no404_string(port:port, host:host))exit(0);

fl[0] = "/_vti_pvt%5caccess.cnf";
fl[1] = "/_vti_pvt%5csvcacl.cnf";
fl[2] = "/_vti_pvt%5cwriteto.cnf";
fl[3] = "/_vti_pvt%5cservice.cnf";
fl[4] = "/_vti_pvt%5cservices.cnf";
fl[5] = "/_vti_pvt%5cbotinfs.cnf";
fl[6] = "/_vti_pvt%5cbots.cnf";
fl[7] = "/_vti_pvt%5clinkinfo.cnf";

for(i = 0 ; fl[i] ; i = i + 1) {
  if(is_cgi_installed_ka(item:fl[i], port:port)){
    res = http_keepalive_send_recv(data:http_get(item:fl[i], port:port), port:port, bodyonly:1);
    data  = "The IIS web server may allow remote users to read sensitive information from .cnf files. This is not the default configuration.";
    data += '\n\nExample : requesting ' + fl[i] + ' produces the following data :\n\n' + res;
    security_message(port:port, data:data);
    exit(0);
  }
}
