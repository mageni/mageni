###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cyrus_imap_server_detect.nasl 13397 2019-02-01 08:06:48Z cfischer $
#
# Cyrus IMAP Server Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902220");
  script_version("$Revision: 13397 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 09:06:48 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Cyrus IMAP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl", "popserver_detect.nasl");
  script_require_ports("Services/imap", 143, 993, "Services/pop3", 110, 995);
  script_mandatory_keys("pop3_imap_or_smtp/banner/available");

  script_tag(name:"summary", value:"This script finds the running version of Cyrus IMAP Server
  and saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("pop3_func.inc");
include("imap_func.inc");
include("host_details.inc");
include("cpe.inc");

ports = imap_get_ports();
foreach port( ports ) {

  banner = get_imap_banner( port:port );
  if( ! banner ) continue;

  if( "Cyrus IMAP" >< banner && "server ready" >< banner ) {

    version = "unknown";

    # e.g. * OK [CAPABILITY IMAP4rev1 LITERAL+ ID ENABLE STARTTLS AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5 AUTH=DIGEST-MD5 SASL-IR] example.com Cyrus IMAP v2.4.17 server ready
    vers = eregmatch(pattern:"IMAP4? v([0-9.]+)", string:banner);
    if( ! isnull( vers[1] ) ) version = vers[1];

    set_kb_item( name:"Cyrus/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cmu:cyrus_imap_server:");
    if( isnull( cpe ) )
      cpe = "cpe:/a:cmu:cyrus_imap_server";

    register_product( cpe:cpe, location:port + "/tcp", port:port, service:"imap" );

    log_message( data:build_detection_report( app:"Cyrus IMAP Server",
                                              version:version,
                                              install:port + "/tcp",
                                              cpe:cpe,
                                              concluded:banner ),
                                              port:port );
  }
}

port = get_pop3_port( default:110 );
banner = get_pop3_banner( port:port );
if( ! banner ) exit( 0 );

if( "Cyrus POP3" >< banner && "server ready" >< banner ) {

  version = "unknown";

  # e.g. +OK example.com Cyrus POP3 v2.4.17 server ready <123@example.com>
  vers = eregmatch(pattern:"POP3 v([0-9.]+)", string:banner);
  if( ! isnull( vers[1] ) ) version = vers[1];

  set_kb_item( name:"Cyrus/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:cmu:cyrus_imap_server:");
  if( isnull( cpe ) )
    cpe = "cpe:/a:cmu:cyrus_imap_server";

  register_product( cpe:cpe, location:port + "/tcp", port:port, service:"pop3" );

  log_message( data:build_detection_report( app:"Cyrus IMAP Server",
                                            version:version,
                                            install:port + "/tcp",
                                            cpe:cpe,
                                            concluded:banner ),
                                            port:port );
}

exit( 0 );