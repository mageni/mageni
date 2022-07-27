###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tandberg_devices_detect.nasl 13627 2019-02-13 10:38:43Z cfischer $
#
# Tandberg Devices Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103694");
  script_version("$Revision: 13627 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:38:43 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-04-11 09:34:17 +0200 (Thu, 11 Apr 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Tandberg Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/tandberg/device/detected");

  script_tag(name:"summary", value:"Detection of Tandberg Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a Tandberg device and extract the codec release from
  the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("host_details.inc");

port = get_telnet_port(default:23);
buf = get_telnet_banner(port:port);
if(!buf || "TANDBERG Codec Release" >!< buf)
  exit(0);

vers = string("unknown");
install = port + '/tcp';

version = eregmatch(string: buf, pattern:string("TANDBERG Codec Release ([^\r\n]+)"), icase:TRUE);
if(!isnull(version[1])) vers = version[1];

set_kb_item(name:"host_is_tandberg_device",value:TRUE);
set_kb_item(name:"tandberg_codec_release", value:vers);
cpe = 'cpe:/h:tandberg:*'; # we don't know which device exactly it is, so just set the base cpe

register_product(cpe:cpe, location:install, port:port, service:"telnet");

message = 'The remote Host is a Tandberg Device.\nCodec Release: ' + vers + '\nCPE: ' + cpe + '\nConcluded: ' + buf + '\n';

log_message(data:message, port:port);

exit(0);