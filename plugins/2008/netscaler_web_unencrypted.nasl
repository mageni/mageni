# OpenVAS Vulnerability Test
# $Id: netscaler_web_unencrypted.nasl 11555 2018-09-22 15:24:22Z cfischer $
# Description: Unencrypted NetScaler web management interface
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2008 nnposter
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

if (description){
  script_oid("1.3.6.1.4.1.25623.1.0.80026");
  script_version("$Revision: 11555 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 17:24:22 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Unencrypted NetScaler web management interface");

  script_family("Web Servers");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (c) 2008 nnposter");
  script_dependencies("netscaler_web_detect.nasl");
  script_mandatory_keys("citrix_netscaler/http/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Consider disabling this port completely and using only HTTPS.");

  script_tag(name:"summary", value:"The remote web management interface does not encrypt connections.

Description :

The remote Citrix NetScaler web management interface does use TLS or
SSL to encrypt connections.");

  script_tag(name:"qod_type", value:"general_note");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");

function is_ssl(port)
{
  local_var encaps;
  encaps = get_port_transport( port );
  if ( encaps && encaps>=ENCAPS_SSLv2 && encaps<=ENCAPS_TLSv12 )
     return TRUE;
   else
     return FALSE;
}


port = get_kb_item("citrix_netscaler/http/port");
if (!port || !get_tcp_port_state(port))
  exit(0);

if (!is_ssl(port:port))
  security_message(port);

exit(0);
