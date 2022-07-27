###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_telnet_unencrypted_cleartext_logins.nasl 13620 2019-02-13 07:44:45Z cfischer $
#
# Telnet Unencrypted Cleartext Login
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.108522");
  script_version("$Revision: 13620 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 08:44:45 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-12-20 07:47:54 +0100 (Thu, 20 Dec 2018)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Telnet Unencrypted Cleartext Login");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"impact", value:"An attacker can uncover login names and passwords by sniffing traffic to the
  Telnet service.");

  script_tag(name:"solution", value:"Replace Telnet with a protocol like SSH which supports encrypted connections.");

  script_tag(name:"summary", value:"The remote host is running a Telnet service that allows cleartext logins over
  unencrypted connections.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = get_telnet_port( default:23 );

# Telnet Secure (TELNETS) on 992/tcp
encaps = get_port_transport( port );
if( encaps > ENCAPS_IP )
  exit( 99 );

# nb: We're currently not supporting a check for START_TLS: https://tools.ietf.org/html/draft-altman-telnet-starttls-02

banner = get_telnet_banner( port:port );
if( ! banner )
  exit( 0 );

# There are plenty of services available which are responding / reporting
# a telnet banner even if those are no telnet services. Only continue with
# the reporting if we actually got a login/password prompt.
if( ! telnet_has_login_prompt( data:banner ) )
  exit( 0 );

# nb: Some banners found "in the wild", e.g. Mitel VoIP phone
if( banner =~ "(For security reasons, a TLS/SSL enabled telnet client MUST be used to connect|Encryption is required\. Access is denied\.)" )
  exit( 99 );

security_message( port:port );
exit( 0 );