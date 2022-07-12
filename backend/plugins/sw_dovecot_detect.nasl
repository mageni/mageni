###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_dovecot_detect.nasl 13397 2019-02-01 08:06:48Z cfischer $
#
# Dovecot POP3/IMAP Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111031");
  script_version("$Revision: 13397 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-01 09:06:48 +0100 (Fri, 01 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-08-26 12:00:00 +0200 (Wed, 26 Aug 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dovecot POP3/IMAP Detection");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("imap4_banner.nasl", "popserver_detect.nasl");
  script_require_ports("Services/imap", 143, 993, "Services/pop3", 110, 995);
  script_mandatory_keys("pop3_imap_or_smtp/banner/available");

  script_tag(name:"summary", value:"The script checks the POP3/IMAP server
  banner for the presence of Dovecot.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("pop3_func.inc");
include("imap_func.inc");

cpe = "cpe:/a:dovecot:dovecot";

# e.g. for IMAP:
# * OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE STARTTLS LOGINDISABLED] Dovecot ready.
# * ID ("name" "Dovecot")
# or POP3:
# +OK Dovecot ready.
pattern = "Dovecot ([a-zA-Z()]+ )?ready";

ports = imap_get_ports();
foreach port( ports ) {

  banner = get_imap_banner( port:port );
  if( egrep( pattern:pattern, string:banner, icase:TRUE ) ||
      'ID ("name" "Dovecot")' >< banner ) {

    version = "unknown";

    set_kb_item( name:"dovecot/detected", value:TRUE );
    set_kb_item( name:"dovecot/imap/detected", value:TRUE );
    set_kb_item( name:"dovecot/imap/port", value:port );

    # Format used in gb_dovecot_consolidation.nasl is:
    # Detection-Name#--#service#--#port#--#location#--#version#--#concluded
    set_kb_item( name:"dovecot/detection-info", value:"IMAP Banner#--#imap#--#" + port + "#--#" + port + "/tcp#--#" + version + "#--#" + chomp( banner ) );
  }
}

port   = get_pop3_port( default:110 );
banner = get_pop3_banner( port:port );

if( egrep( pattern:pattern, string:banner, icase:TRUE ) ) {

  version = "unknown";

  set_kb_item( name:"dovecot/detected", value:TRUE );
  set_kb_item( name:"dovecot/pop3/detected", value:TRUE );
  set_kb_item( name:"dovecot/pop3/port", value:port );

  # Format used in gb_dovecot_consolidation.nasl is:
  # Detection-Name#--#service#--#port#--#location#--#version#--#concluded
  set_kb_item( name:"dovecot/detection-info", value:"POP3 Banner#--#pop3#--#" + port + "#--#" + port + "/tcp#--#" + version + "#--#" + chomp( banner ) );
}

exit( 0 );