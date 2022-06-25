#############################################################################
# OpenVAS Vulnerability Test
# $Id: mailenable_smtp_dos.nasl 13467 2019-02-05 12:16:48Z cfischer $
#
# MailEnable SMTP Connector Service DNS Lookup DoS Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
#############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14712");
  script_version("$Revision: 13467 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 13:16:48 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_bugtraq_id(11144);
  script_name("MailEnable SMTP Connector Service DNS Lookup DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Denial of Service");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/mailenable/detected");

  script_tag(name:"impact", value:"A remote attacker can exploit this to perform a DoS attack against the
  SMTP server on the target.");

  script_tag(name:"solution", value:"Upgrade to MailEnable Standard Edition 1.8 / Professional
  Edition 1.5e or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of MailEnable's SMTP
  Connector service. A flaw exists in both the Standard Edition 1.7x and Professional Edition
  1.2x/1.5a-e that results in this service crashing if it receives a DNS response with over 100 MX records.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("version_func.inc");

port = get_smtp_port( default:25 );

# We have to rely only on the banner, which unfortunately is not updated by the hotfix.
banner = get_smtp_banner( port:port );
if( ! banner || banner !~ "Mail(Enable| Enable SMTP) Service" )
  exit( 0 );

# nb: Standard Edition seems to format version as "1.71--" (for 1.71)
#     while Professional Edition formats it like "0-1.2-" (for 1.2).
ver = eregmatch( pattern:"Version: (0-)?([0-9][^-]+)-", string:banner, icase:TRUE );
if( isnull( ver ) ) {
  exit( 0 );
}
if( isnull( ver[1] ) ) {
  edition = "Standard Edition";
}
else if( ver[1] == "0-" ) {
  edition = "Professional Edition";
}
if( isnull( edition ) ) {
  exit( 0 );
}
ver = ver[2];

if( edition == "Standard Edition" ) {
  # nb: see <http://www.mailenable.com/standardhistory.html> for history.
  if( ver =~ "^1\.7" ) {
    report = report_fixed_ver( installed_ver:edition + " " + ver, fixed_version:edition + " 1.8" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}
else if( edition == "Professional" ) {
  # nb: there were no version 1.3x or 1.4x; see <http://www.mailenable.com/professionalhistory.html>.
  if( ver =~ "^1\.(2|5[a-e])" ) {
    report = report_fixed_ver( installed_ver:edition + " " + ver, fixed_version:edition + " 1.5e" );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );