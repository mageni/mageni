###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_mailserver_detect.nasl 13688 2019-02-15 10:21:10Z cfischer $
#
# Kerio MailServer/Connect Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800098");
  script_version("$Revision: 13688 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:21:10 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Kerio MailServer/Connect Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("httpver.nasl", "smtpserver_detect.nasl", "popserver_detect.nasl", "imap4_banner.nasl", "nntpserver_detect.nasl");
  script_require_ports("Services/www", 80, 443, "Services/smtp", 25, 465, 587, "Services/pop3", 110, 995,
                       "Services/imap", 143, 993, "Services/nntp", 119);

  script_tag(name:"summary", value:"This script will detect the version of Kerio MailServer or Connect
  on the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("pop3_func.inc");
include("imap_func.inc");
include("smtp_func.inc");

ports = make_array();
report = ""; # nb: To make openvas-nasl-lint happy...
cgi_disabled = http_is_cgi_scan_disabled();

smtpPorts = smtp_get_ports();
foreach smtpPort( smtpPorts )
  ports[smtpPort] = "smtp";

imapPorts = imap_get_ports();
foreach imapPort( imapPorts )
  ports[imapPort] = "imap";

popPorts = pop3_get_ports();
foreach popPort( popPorts )
  ports[popPort] = "pop3";

httpPorts = http_get_ports();
foreach httpPort( httpPorts )
  ports[httpPort] = "www";

nntpPorts = get_kb_list( "Services/nntp" );
if( ! nntpPorts ) nntpPorts = make_list( 119 );
foreach nntpPort( nntpPorts )
  ports[nntpPort] = "nntp";

foreach port( keys( ports ) ) {

  if( ! get_port_state( port ) ) continue;
  service = ports[port];

  if( service == "smtp" ) {
    banner = get_smtp_banner( port:port );
  } else if( service == "imap" ) {
    banner = get_imap_banner( port:port );
  } else if( service == "pop3" ) {
    banner = get_pop3_banner( port:port );
  } else if( service == "www" ) {
    if( cgi_disabled ) continue;
    banner = get_http_banner( port:port );
    banner = egrep( string:banner, pattern: "^Server: .*", icase:TRUE );
  } else if( service == "nntp" ) { # nb: The NNTP Service seems to be running on Kerio Connect only
    banner = get_kb_item( "nntp/banner/" + port );
  } else {
    continue; # nb: something went wrong
  }

  if( ! banner ) continue;
  if( "Kerio MailServer" >!< banner && "Kerio Connect" >!< banner ) continue;

  version = "unknown";
  def_cpe = "cpe:/a:kerio:kerio_mailserver";
  server  = "MailServer";
  install = port + "/tcp";

  # Kerio Connect #
  # IMAP:
  # * OK IMAP4rev1 server ready
  # * ID ("name" "Kerio Connect")
  # but also:
  # * OK Kerio Connect 8.0.2 IMAP4rev1 server ready
  # * ID ("name" "Kerio Connect" "version" " 8.0.2 ")
  # HTTP:
  # Server: Kerio Connect 9.2.1
  # SMTP:
  # 220 example.com Kerio Connect 9.2.1 ESMTP ready
  # NNTP:
  # 200 Kerio Connect 8.0.2 NNTP server ready
  # 200 Kerio Connect 9.2.5 patch 3 NNTP server ready
  #
  # Kerio MailServer #
  # HTTP:
  # Server: Kerio MailServer 6.5.2
  # Server: Kerio MailServer 6.6.2
  # POP3:
  # +OK Kerio MailServer 6.5.2 POP3 server ready <1168.1533545939@example.com>
  # SMTP:
  # 220 example.com Kerio MailServer 6.5.2 ESMTP ready
  # IMAP:
  # * OK Kerio MailServer 6.6.2 IMAP4rev1 server ready
  # * ID ("name" "Kerio MailServer" "version" " 6.6.2 ")
  vers_nd_type = eregmatch( pattern:"Kerio (MailServer|Connect) ([0-9.]+)(-| )?([a-zA-Z]+ [0-9]+)?", string:banner );

  if( ! isnull( vers_nd_type[1] ) ) {
    server = vers_nd_type[1];
    if( server == "Connect" )
      def_cpe = "cpe:/a:kerio:connect";
  }

  if( ! isnull( vers_nd_type[2] ) ) {
    if( ! isnull( vers_nd_type[4] ) ) {
      version = vers_nd_type[2] + "." + vers_nd_type[4];
    } else {
      version = vers_nd_type[2];
    }
    version = ereg_replace( pattern:" ", replace:"", string:version );
  }

  set_kb_item( name:"KerioMailServer/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+([a-z0-9]+)?)", base:def_cpe + ":" );
  if( isnull( cpe ) )
    cpe = def_cpe;

  register_product( cpe:cpe, location:install, port:port, service:service );

  if( report ) report += '\n';
  report += build_detection_report( app:"Kerio " + server,
                                    version:version,
                                    install:install,
                                    cpe:cpe,
                                    concluded:banner );

}

if( strlen( report ) > 0 ) {
  log_message( port:0, data:report );
}

exit( 0 );