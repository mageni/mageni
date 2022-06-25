##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_openview_nnm_detect.nasl 8139 2017-12-15 11:57:25Z cfischer $
#
# HP OpenView Network Node Manager Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900242");
  script_version("$Revision: 8139 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:57:25 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HP OpenView Network Node Manager Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 7510);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of HP OpenView Network
  Node Manager and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:7510 );

req = http_get( item:"/topology/home", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ( "Network Node Manager Home Base" >< res || "hp OpenView Network Node Manager" >< res ) &&
      egrep( pattern:"Copyright \(c\).* Hewlett-Packard", string:res ) &&
      res =~ "HTTP/1\.. 200" ) {

  version = "unknown";
  install = "/";

  ## Extract Version from the response and set the KB
  vers = eregmatch( pattern:">NNM Release ([0-9a-zA-Z\.]+)<", string:res );

  if( vers != NULL ) {
    version = vers[1];
    set_kb_item( name:"www/"+ port + "/HP/OVNNM/Ver", value:version );
  }

  set_kb_item( name:"HP/OVNNM/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:hp:openview_network_node_manager:" );
  if( ! cpe )
    cpe = 'cpe:/a:hp:openview_network_node_manager';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"HP OpenView Network Node Manager",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );