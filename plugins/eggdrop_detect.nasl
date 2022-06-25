###############################################################################
# OpenVAS Vulnerability Test
# $Id: eggdrop_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Eggdrop Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.100206");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-05-16 14:32:16 +0200 (Sat, 16 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Eggdrop Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/eggdrop", 3333);
  script_tag(name:"summary", value:"This Host is running Eggdrop, an Open Source IRC bot.");

  script_xref(name:"URL", value:"http://www.eggheads.org/");

  script_timeout(3600);

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("telnet_func.inc");

port = get_kb_item("Services/eggdrop");

if(!port)
 port = 3333;

if(!get_port_state(port))exit(0);

# Eggdrop probably uses some reverse lookup or identd requests, so we use a rather large timeout
banner = get_telnet_banner(port:port, timeout: 20);

if(isnull(banner))
   exit(0);

if(egrep(pattern:"Eggdrop", string: banner, icase:TRUE)) {
  version = eregmatch(string: banner, pattern: "\(Eggdrop v([0-9.]+[^ ]*) \(",icase:TRUE);

  if (!isnull(version[1]))
    vers = version[1];

  set_kb_item(name: "eggdrop/installed", value: TRUE);

  cpe = build_cpe(value: vers, exp:"^([0-9a-z+.]+)",base:"cpe:/a:eggheads:eggdrop:");
  if (!cpe)
    cpe = 'cpe:/a:eggheads:eggdrop';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Eggdrop", version: vers, install: "/", cpe: cpe,
                                           concluded: version[1]),
              port: port);
  exit(0);
}

exit(0);
