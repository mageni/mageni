###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_reflection_secureit_unix_detect_lin.nasl 13577 2019-02-11 13:30:15Z cfischer $
#
# Reflection for Secure IT Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800227");
  script_version("$Revision: 13577 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 14:30:15 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Reflection for Secure IT Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/reflection/secureit/detected");

  script_tag(name:"summary", value:"The script tries to detect Reflections for Secure IT and its
  version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

SCRIPT_DESC = " Version Detection (Linux)";

port = get_ssh_port( default:22 );
banner = get_ssh_server_banner( port:port );
if( ! banner || banner !~ "^SSH\-.*ReflectionForSecureIT" )
  exit( 0 );

set_kb_item( name:"attachmate/reflection_for_secure_it/detected", value:TRUE );

version = "unknown";
install = port + "/tcp";

vers = eregmatch( pattern:"SSH\-.*ReflectionForSecureIT_([0-9.]+)", string:banner );
if( vers[1] )
  version = vers[1];

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:attachmate:reflection_for_secure_it:");
if( ! cpe )
  cpe = "cpe:/a:attachmate:reflection_for_secure_it";

register_product( cpe:cpe, location:install, port:port, service:"ssh" );

log_message( data:build_detection_report(app:"Reflection for Secure IT",
                                         version:version,
                                         install:install,
                                         cpe:cpe,
                                         concluded:banner),
                                         port:port );

exit( 0 );