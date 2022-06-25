###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_prosafe_http_detect.nasl 8020 2017-12-07 08:09:44Z cfischer $
#
# NETGEAR ProSAFE Devices Detection (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108308");
  script_version("$Revision: 8020 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:09:44 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-05 09:03:31 +0100 (Tue, 05 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NETGEAR ProSAFE Devices Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based detection of NETGEAR ProSAFE devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
buf  = http_get_cache( item:"/", port:port );

# nb: Note that NETGEAR has switched the writing of their name and brandings between the years,
# which changed between firmwares of e.g. the same device
# GS108Ev3 with different firmwares:
#<title>NETGEAR ProSAFE Plus Switch</title>
#<title>Netgear Prosafe Plus Switch</title>
#<div class="switchInfo">GS108Ev3 - 8-Port Gigabit ProSAFE Plus Switch</div>
#
#<TITLE>NetGear GSM7224V2</TITLE>	<!-- Netgear Page Title		-->
#<TITLE>NETGEAR GSM7224V2</TITLE>	<!-- Netgear Page Title		-->
#<title>NetGear GS108TV1</title>
#
#<TITLE>Netgear System Login</TITLE>
#<IMG SRC = "/base/images/netgear_gsm7224_banner.gif" ALIGN="CENTER">

if( buf =~ "^HTTP/1\.[01] 200" &&
    ( "<title>NETGEAR ProSAFE" >< buf ||
      "<title>Netgear Prosafe" >< buf ||
      '<div class="switchInfo">.*ProSAFE.*</div>' >< buf ||
      ( egrep( pattern:"<title>netgear", string:buf, icase:TRUE ) &&
        ( "/base/images/netgear_" >< buf || "/base/netgear_login.html" >< buf || buf =~ "<td>Copyright &copy; .* Netgear &reg;</td>" || "login.cgi" >< buf )
      )
    )
  ) {

  model      = "unknown";
  fw_version = "unknown";
  fw_build   = "unknown";

  mod = eregmatch( pattern:'<div class="switchInfo">([0-9a-zA-Z\\-]+)[^\r\n]+</div>', string:buf, icase:TRUE );
  if( mod[1] ) {
    model = mod[1];
    set_kb_item( name:"netgear/prosafe/http/" + port + "/concluded", value:mod[0] );
  } else {
    mod = eregmatch( pattern:"/base/images/netgear_([0-9a-zA-Z\\-]+)_banner.gif", string:buf, icase:TRUE );
    if( mod[1] ) {
      model = mod[1];
      set_kb_item( name:"netgear/prosafe/http/" + port + "/concluded", value:mod[0] );
    } else {
      mod = eregmatch( pattern:"<TITLE>NetGear ([0-9a-zA-Z\\-]+)</TITLE>", string:buf, icase:TRUE );
      if( mod[1] ) {
        model = mod[1];
        set_kb_item( name:"netgear/prosafe/http/" + port + "/concluded", value:mod[0] );
      }
    }
  }

  set_kb_item( name:"netgear/prosafe/http/" + port + "/model", value:model );
  set_kb_item( name:"netgear/prosafe/http/" + port + "/fw_version", value:fw_version );
  set_kb_item( name:"netgear/prosafe/http/" + port + "/fw_build", value:fw_build );
  set_kb_item( name:"netgear/prosafe/http/detected", value:TRUE );
  set_kb_item( name:"netgear/prosafe/http/port", value:port );
  set_kb_item( name:"netgear/prosafe/detected", value:TRUE );
}

exit( 0 );
