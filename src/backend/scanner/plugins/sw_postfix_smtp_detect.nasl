# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111086");
  script_version("2024-01-12T05:05:56+0000");
  script_tag(name:"last_modification", value:"2024-01-12 05:05:56 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-02-04 17:00:00 +0100 (Thu, 04 Feb 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Postfix SMTP Server Detection (SMTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("smtpserver_detect.nasl", "check_smtp_helo.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("smtp/banner/available");

  script_xref(name:"URL", value:"https://www.postfix.org/");

  script_tag(name:"summary", value:"SMTP based detection of Postfix.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");
include("cpe.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = smtp_get_port( default:25 );
banner = smtp_get_banner( port:port );

quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );

# 220 mail.example.com ESMTP Postfix (Debian/GNU)
# 220 mail.example.com ESMTP Postfix
# 220 mail.example.com ESMTP Postfix (Ubuntu)
# 220 ESMTP Postfix 2.5.5
# 220 mail.example.com ESMTP Postfix (3.5.23)
# 220 mail.example.com ESMTP Postfix (3.8-20230121)
# 220 mail.example.com ESMTP Postfix (2.0.6) (Mandrake Linux)
#
# If the banner is over two lines it might look like this:
# 220-mail.example.com ESMTP Postfix
# 220-<someadditionaltext>
#
# From https://mailinabox.email which seems to use Postfix internally:
# 220 mail.example.com ESMTP Hi, I'm a Mail-in-a-Box (Ubuntu/Postfix; see https://mailinabox.email/)
# 220 mail.example.com ESMTP Power Mail-in-a-Box (Postfix)
#
# The purpose of the "3" here is currently unknown:
# 220 mail.example.com ESMTP Postfix :3
# 220 mail.example.com ESMTP Postfix +3 smtp3-submit
#
if( "ESMTP Postfix" >< banner || "Ubuntu/Postfix;" >< banner || "Power Mail-in-a-Box (Postfix)" >< banner ) {
  found = TRUE;
  concluded = banner;
}

if( ! found ) {
  if( "Bye" >< quit && "Ok" >< noop && "Error: command not recognized" >< help && "Ok" >< rset ) {
    found = TRUE;
    concluded = "  From fingerprinting based on the following SMTP command responses:";
    concluded += '\n  - "QUIT": ' + quit;
    concluded += '\n  - "NOOP": ' + noop;
    concluded += '\n  - "HELP": ' + help;
    concluded += '\n  - "RSET": ' + rset;
  }
}

if( found ) {

  install = port + "/tcp";
  version = "unknown";

  vers = eregmatch( pattern:"220.+Postfix \(([0-9.]+)[^)]*\)", string:banner );
  if( ! vers[1] ) {
    # nb: The regex pattern was made a little bit more strict here to prevent possible false
    # extraction from things like e.g.:
    # 220 mail.example.com ESMTP Postfix :3
    vers = eregmatch( pattern:"220.+Postfix ([0-9]+\.[0-9.]+)", string:banner );
  }

  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"postfix/detected", value:TRUE );
  set_kb_item( name:"postfix/smtp/detected", value:TRUE );
  set_kb_item( name:"postfix/smtp/" + port + "/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:postfix:postfix:" );
  if( ! cpe )
    cpe = "cpe:/a:postfix:postfix";

  register_product( cpe:cpe, location:install, port:port, service:"smtp" );

  log_message( data:build_detection_report( app:"Postfix",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded ),
               port:port );
}

exit( 0 );
