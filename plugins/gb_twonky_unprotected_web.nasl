###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twonky_unprotected_web.nasl 10712 2018-08-01 14:15:12Z cfischer $
#
# Twonky Server Unprotected Web Console
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:twonky:twonky_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108007");
  script_version("$Revision: 10712 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-01 16:15:12 +0200 (Wed, 01 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-09-28 12:00:00 +0200 (Wed, 28 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Twonky Server Unprotected Web Console");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_twonky_server_detect.nasl");
  script_require_ports("Services/www", 9000);
  script_mandatory_keys("twonky_server/installed");

  script_tag(name:"summary", value:"The remote Twonky Server web console is not protected by a username and password.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that
  may lead to further attacks or change the configuration of the device.");

  script_tag(name:"vuldetect", value:"Check with a GET request if the URL /rpc/info_status is protected by a username
  and password.");

  script_tag(name:"affected", value:"All systems running Twonky Server.");

  script_tag(name:"solution", value:"Set a username and password within the 'Advanced' settings of this device.

  Older versions of Twonky Server are not supporting the protection of the web console with a username and password.
  Restrict access to such older devices.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

host = http_host_name( dont_add_port:TRUE );
install = dir;
if( dir == "/" ) dir = "";
url = dir + "/rpc/info_status";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( buf =~ "HTTP/1.. 401" ) {
  set_kb_item( name:"www/content/auth_required", value:TRUE );
  set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );
}

if( buf =~ "HTTP/1.. 200" && ( "serverkind|" >< buf || "serverplatform|" >< buf || "version|" >< buf ) ) {
  report = report_vuln_url( port:port, url:install );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
