# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105189");
  script_version("2024-01-12T05:05:56+0000");
  script_tag(name:"last_modification", value:"2024-01-12 05:05:56 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2015-01-29 15:29:06 +0100 (Thu, 29 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Exim SMTP Server Detection (SMTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/banner/available");

  script_xref(name:"URL", value:"https://www.exim.org/");

  script_tag(name:"summary", value:"SMTP based detection of Exim.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");
include("cpe.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port( default:25 );
banner = smtp_get_banner( port:port );

quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );

# 220 mail.example.com ESMTP Exim 4.96.2-12-g29d01ae2a Wed, 10 Jan 2024 11:03:45 +0100
# 220 mail.example.com ESMTP Exim 4.93 Ubuntu Wed, 10 Jan 2024 13:03:50 +0300
# 220-mail.example.com ESMTP Exim 4.93 #2 Wed, 10 Jan 2024 19:03:42 +0900
# 220 mail.example.com ESMTP Exim 4.84 Wed, 10 Jan 2024 05:08:26 -0500
# 220 mail.example.com ESMTP Exim 4.97.1 Wed, 10 Jan 2024 05:10:28 -0500
# 220 mail.example.com ESMTP Exim 3.10 2024-01-10T10:03:52+00:00
# 220 mail.example.com ESMTP Exim 4.97-RC1 Wed, 10 Jan 2024 09:17:33 +0100
# 220 mail.example.com ESMTP Exim 4.90_1 Ubuntu Wed, 10 Jan 2024 10:11:00 +0000
#
# If the banner is over two lines it might look like this:
# 220-mail.example.com ESMTP Exim 4.96.2 #2 Thu, 11 Jan 2024 02:50:52 -0600
# 220-<someadditionaltext>
#
if( "ESMTP Exim" >< banner ) {
  found = TRUE;
  concluded = banner;
}

if( ! found ) {
  if( "closing connection" >< quit && "OK" >< noop && "Commands supported:" >< help && "Reset OK" >< rset ) {
    found = TRUE;
    concluded = "  From fingerprinting based on the following SMTP command responses:";
    concluded += '\n  - "QUIT": ' + quit;
    concluded += '\n  - "NOOP": ' + noop;
    concluded += '\n  - "HELP": ' + help;
    concluded += '\n  - "RSET": ' + rset;
  }
}

if( found ) {

  version = "unknown";
  install = port + "/tcp";

  vers = eregmatch( pattern:"ESMTP Exim ([0-9.]+(_[0-9]+)?)", string:banner );
  if( vers[1] )
    version = vers[1];

  if( "_" >< version )
    version = str_replace( string:version, find:"_", replace:"." );

  set_kb_item( name:"exim/detected", value:TRUE );
  set_kb_item( name:"exim/smtp/detected", value:TRUE );
  set_kb_item( name:"exim/smtp/" + port + "/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:exim:exim:" );
  if( ! cpe )
    cpe = "cpe:/a:exim:exim";

  register_product( cpe:cpe, location:install, port:port, service:"smtp" );

  log_message( data:build_detection_report( app:"Exim",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded ),
               port:port );
}

exit( 0 );
