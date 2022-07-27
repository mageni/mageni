###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_openstage_sip_web_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# OpenStage SIP Webinterface Default Password
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111058");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OpenStage SIP Webinterface Default Password");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-11-24 14:00:00 +0100 (Tue, 24 Nov 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:'The remote OpenStage SIP Webinterface is prone to a
  default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
  access to sensitive information.');

  script_tag(name:"vuldetect", value:'Try to login with a default password.');
  script_tag(name:"insight", value:'It was possible to login with the Admin user and the default
  password "123456".');
  script_tag(name:"solution", value:'Change the password.');

  script_xref(name:"URL", value:"http://wiki.unify.com/wiki/OpenStage_SIP_FAQ#What_are_the_default_passwords.3F");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

req = http_get( item: "/index.cmd?user=Admin", port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Openstage IP Phone Admin</title>" >< res || "Unify GmbH & Co. KG, www.unify.com" >< res ||
    "Siemens AG, www.siemens.com" >< res ) {

  host = http_host_name( port:port );

  # Different login pattern for Unify/Siemens OpenStage 40/60
  loginData = make_list( "page_submit=WEBMp_Admin_Login&page-next=WEBM_Admin_IpConfiguration&AdminPassword=123456",
                         "page_submit=WEBMp_AdminLogin&page-next=WEBM_Admin_IpConfiguration&WEBMv-Admin-Password=123456",
                         "page_submit=WEBMp_AdminLogin&page-next=WEBM_Admin_IpConfiguration&AdminPassword=123456" );

  foreach data ( loginData ) {
    useragent = http_get_user_agent();

    len = strlen( data );

    req = 'POST /page.cmd HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Content-Type: application/x-www-form-urlencoded\r\n' +
          'Content-Length: ' + len + '\r\n' +
          '\r\n' +
          data;
    res = http_keepalive_send_recv( port:port, data:req );

    if( "IP configuration" >< res || "Subnet mask" >< res ||
        "Default route" >< res || "Primary DNS" >< res ) {
      report = 'It was possible to login using the following password:\n\n123456\n';
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
