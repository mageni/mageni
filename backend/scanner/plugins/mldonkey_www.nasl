###############################################################################
# OpenVAS Vulnerability Test
# $Id: mldonkey_www.nasl 9608 2018-04-25 13:33:05Z jschulte $
#
# MLDonkey web interface detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Modified by Michael Meyer
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# Note: this script is not very useful because mldonkey only allows
# connections from localhost by default

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11125");
  script_version("$Revision: 9608 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-25 15:33:05 +0200 (Wed, 25 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("MLDonkey web interface detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 4080);
  script_mandatory_keys("MLDonkey/banner");

  script_tag(name:"solution", value:"Disable it");
  script_tag(name:"summary", value:"MLDonkey web interface might be running on this port. This peer to peer
  software is used to share files.

  1. This may be illegal.
  2. You may have access to confidential files
  3. It may eat too much bandwidth");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:4080 );

banner = get_http_banner( port:port );

if( ! banner ) exit( 0 );

if( egrep( pattern:"MLDonkey", string:banner, icase:TRUE ) ) {
  if( ! egrep( pattern:"failure", string:banner, icase:TRUE ) ) {

    vers = "unknown";
    install = "/";

    if( ereg( pattern:"^HTTP/1\.[01] +403", string:banner ) ) {
      version = eregmatch( string:banner, pattern:"MLDonkey/([0-9]+\.*[0-9]*\.*[0-9]*)+" );
      if( ! isnull( version[1] ) ) vers = version[1];
    } else if( ereg( pattern:"^HTTP/1\.[01] +200", string:banner)  ) {
      req = http_get( item:"/oneframe.html", port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      version = eregmatch( string:buf, pattern:"Welcome to MLDonkey ([0-9]+\.*[0-9]*\.*[0-9]*).*" );
      if( ! isnull( version[1] ) ) vers = version[1];
      if( ! islocalhost() ) ml_www_remote = TRUE;
    }

    report = string( "MLDonkey Version (" );
    report += vers;
    report += string( ") was detected on the remote host.\n" );
    if( ml_www_remote ) {
      report += string( "\nRemote access to MLDonkey web interface from " );
      report += this_host_name();
      report += string( " is allowed!\n" );
      set_kb_item( name:"www/" + port + "/MLDonkey/remote/", value:TRUE );
    }

    tmp_version = vers + " under " + install;
    set_kb_item( name: "www/" + port + "/MLDonkey/version", value:tmp_version );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+-?([a-z0-9]+)?)", base:"cpe:/a:mldonkey:mldonkey:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:mldonkey:mldonkey";

    register_product( cpe:cpe, location:install, port:port );

    set_kb_item( name:"MLDonkey/www/port/", value:port );

    log_message( port:port, data:report );
  }
}

exit( 0 );
