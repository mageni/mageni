###############################################################################
# OpenVAS Vulnerability Test
# $Id: smtpserver_detect.nasl 14004 2019-03-05 17:53:23Z cfischer $
#
# SMTP Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10263");
  script_version("$Revision: 14004 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 18:53:23 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SMTP Server type and version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 SecuriTeam");
  script_family("Service detection");
  script_dependencies("find_service_3digits.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"summary", value:"This detects the SMTP Server's type and version by connecting to
  the server and processing the buffer received.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");
include("misc_func.inc");

ports = smtp_get_ports();
foreach port( ports ) {

  # nb: get_smtp_banner is verifying that we're receiving an expected SMTP response so its
  # safe to use a register_service below.
  banner = get_smtp_banner( port:port );
  if( ! banner )
    continue;

  guess    = NULL;
  commands = NULL;

  if( service_is_unknown( port:port ) )
    register_service( port:port, proto:"smtp", message:"A SMTP Server seems to be running on this port." );

  set_kb_item( name:"smtp/banner/available", value:TRUE );
  set_kb_item( name:"pop3_imap_or_smtp/banner/available", value:TRUE );

  quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
  help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
  rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );
  if( get_port_transport( port ) > ENCAPS_IP ) {
    ehlo = get_kb_item( "smtp/fingerprints/" + port + "/tls_ehlo_banner" );
    is_tls = TRUE;
  } else {
    ehlo = get_kb_item( "smtp/fingerprints/" + port + "/nontls_ehlo_banner" );
    is_tls = FALSE;
  }

  if( "qmail" >< banner || "qmail" >< help ) {
    set_kb_item( name:"smtp/qmail/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/qmail/detected", value:TRUE );
    guess += '\n- Qmail';
  }

  if( "XMail " >< banner ) {
    set_kb_item( name:"smtp/xmail/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/xmail/detected", value:TRUE );
    guess += '\n- XMail';
  }

  if( egrep( pattern:".*nbx.*Service ready.*", string:banner ) ) {
    set_kb_item( name:"smtp/3comnbx/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/3comnbx/detected", value:TRUE );
    guess += '\n- 3comnbx';
  }

  if( "ZMailer Server" >< banner ||
      ( "This mail-server is at Yoyodyne Propulsion Inc." >< help && # Default help text.
        "Out" >< quit && "zmhacks@nic.funet.fi" >< help ) ) {
    set_kb_item( name:"smtp/zmailer/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/zmailer/detected", value:TRUE );
    str = egrep( pattern:" ZMailer ", string:banner );
    if( str ) {
      str = ereg_replace( pattern:"^.*ZMailer Server ([0-9a-z\.\-]+) .*$", string:str, replace:"\1" );
      guess += '\n- ZMailer version ' + str;
    } else {
      guess += '\n- ZMailer';
    }
  }

  if( "CheckPoint FireWall-1" >< banner ) {
    set_kb_item( name:"smtp/firewall-1/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/firewall-1/detected", value:TRUE );
    guess += '\n- CheckPoint FireWall-1';
  }

  if( "InterMail" >< banner ||
      ( "This SMTP server is a part of the InterMail E-mail system" >< help &&
        "Ok resetting state." >< rset && "ESMTP server closing connection." >< quit ) ) {
    set_kb_item( name:"smtp/intermail/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/intermail/detected", value:TRUE );
    str = egrep( pattern:"InterMail ", string:banner );
    if( str ) {
      str = ereg_replace( pattern:"^.*InterMail ([A-Za-z0-9\.\-]+).*$", string:str, replace:"\1" );
      guess += '\n- InterMail version ' + str;
    } else {
      guess += '\n- InterMail';
    }
  }

  if( "mail rejector" >< banner ||
      ( ehlo && match( pattern:"*snubby*", string:ehlo, icase:TRUE ) ) ) {
    set_kb_item( name:"smtp/snubby/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/snubby/detected", value:TRUE );
    smtp_set_is_marked_wrapped( port:port );
    guess  += '\n- Snubby Mail Rejector (not a real SMTP server)';
    report  = "Verisign mail rejector appears to be running on this port. You probably mistyped your hostname and the scanner is scanning the wildcard address in the .COM or .NET domain.";
    report += '\n\nSolution: enter a correct hostname';
    log_message( port:port, data:report );
  }

  if( egrep( pattern:"Mail(Enable| Enable SMTP) Service", string:banner ) ) {
    set_kb_item( name:"smtp/mailenable/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/mailenable/detected", value:TRUE );
    guess += '\n- MailEnable SMTP';
  }

  if( " MDaemon " >< banner ) {
    set_kb_item( name:"smtp/mdaemon/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/mdaemon/detected", value:TRUE );
    guess += '\n- MDaemon SMTP';
  }

  if( " InetServer " >< banner ) {
    set_kb_item( name:"smtp/inetserver/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/inetserver/detected", value:TRUE );
    guess += '\n- A-V Tronics InetServ SMTP';
  }

  if( "Quick 'n Easy Mail Server" >< banner ) {
    set_kb_item( name:"smtp/quickneasy/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/quickneasy/detected", value:TRUE );
    guess += '\n' + "- Quick 'n Easy Mail Server";
  }

  if( "QK SMTP Server" >< banner ) {
    set_kb_item( name:"smtp/qk_smtp/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/qk_smtp/detected", value:TRUE );
    guess += '\n- QK SMTP Server';
  }

  if( "ESMTP CommuniGate Pro" >< banner ) {
    set_kb_item( name:"smtp/communigate/pro/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/communigate/pro/detected", value:TRUE );
    guess += '\n- CommuniGate Pro';
  }

  if( "TABS Mail Server" >< banner ) {
    set_kb_item( name:"smtp/tabs/mailcarrier/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/tabs/mailcarrier/detected", value:TRUE );
    guess += '\n- TABS MailCarrier';
  }

  if( "ESMTPSA" >< banner ) {
    set_kb_item( name:"smtp/esmtpsa/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/esmtpsa/detected", value:TRUE );
    guess += '\n- Various Mail Server like Rumble SMTP';
  }

  if( banner =~ "^220 [^ ]+ ESMTP$" || "Powered by the new deepOfix Mail Server" >< banner || "Welcome to deepOfix" >< banner || "qmail" >< help ) {
    set_kb_item( name:"smtp/deepofix/detected", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/deepofix/detected", value:TRUE );
    guess += '\n- deepOfix';
  }

  report = 'Remote SMTP server banner:\n\n' + banner;
  if( strlen( guess ) > 0 )
    report += '\n\nThis is probably:\n' + guess;

  if( is_tls )
    commandlist = get_kb_list( "smtp/fingerprints/" + port + "/tls_commandlist" );
  else
    commandlist = get_kb_list( "smtp/fingerprints/" + port + "/nontls_commandlist" );

  if( commandlist && is_array( commandlist ) ) {
    # Sort to not report changes on delta reports if just the order is different
    commandlist = sort( commandlist );
    foreach command( commandlist ) {
      if( ! commands )
        commands = command;
      else
        commands += ", " + command;
    }
  }

  if( strlen( commands ) > 0 ) {
    ehlo_report = '\n\nThe remote SMTP server is announcing the following available ESMTP commands (EHLO response) via an ';
    if( is_tls )
      ehlo_report += "encrypted";
    else
      ehlo_report += "unencrypted";
    report += ehlo_report += ' connection:\n\n' + commands;
  }

  log_message( port:port, data:report );
}

exit( 0 );