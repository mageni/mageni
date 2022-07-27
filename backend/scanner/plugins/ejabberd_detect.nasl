###############################################################################
# OpenVAS Vulnerability Test
# $Id: ejabberd_detect.nasl 11028 2018-08-17 09:26:08Z cfischer $
#
# ejabberd Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100486");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11028 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 11:26:08 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("ejabberd Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("xmpp_detect.nasl");
  script_require_ports("Services/xmpp", 5222);

  script_tag(name:"summary", value:"This host is running ejabberd, an instant messaging server.");

  script_xref(name:"URL", value:"http://www.process-one.net/en/ejabberd/");

  exit(0);
}

include("global_settings.inc");
include("host_details.inc");

SCRIPT_DESC = "ejabberd Detection";

xmpp_port = get_kb_item("Services/xmpp");
if(!xmpp_port)xmpp_port=5222;
if(!get_port_state(xmpp_port))exit(0);

server = get_kb_item(string("xmpp/", xmpp_port, "/server"));
if("ejabberd" >< server) {
  version = get_kb_item(string("xmpp/", xmpp_port, "/version"));
  if(!isnull(version)) {
    set_kb_item(name: string("xmpp/", xmpp_port, "/ejabberd"), value: version);
    register_host_detail(name:"App", value:string("cpe:/a:process-one:ejabberd:",version), desc:SCRIPT_DESC);
    info = string("\n\nejabberd version '", version, "' was detected by OpenVAS.\n");
    if(report_verbosity > 0) {
      log_message(port:xmpp_port,data:info);
    }
    KB_SET = TRUE;
  }
}

include("http_func.inc");
include("http_keepalive.inc");

port = 5280;
if(!get_port_state(port))exit(0);

url = string("/admin/doc/README.txt");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )exit(0);

if("Release Notes" >< buf && "ejabberd" >< buf)
{
  ver = eregmatch(string: buf, pattern: "ejabberd ([0-9.]+)",icase:TRUE);

  if ( !isnull(ver[1]) ) {

    version=chomp(ver[1]);

    if(!KB_SET) {
      set_kb_item(name: string("xmpp/", xmpp_port, "/ejabberd"), value: version);
      register_host_detail(name:"App", value:string("cpe:/a:process-one:ejabberd:",version), desc:SCRIPT_DESC);
    }

    info = string("ejabberd Web Admin (ejabberd version '",version,"') is running at this port.\n");
    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
