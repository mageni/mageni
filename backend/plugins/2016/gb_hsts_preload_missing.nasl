###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hsts_preload_missing.nasl 7385 2017-10-09 12:02:13Z cfischer $
#
# SSL/TLS: "preload" Missing in HSTS Header
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105878");
  script_version("$Revision: 7385 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-09 14:02:13 +0200 (Mon, 09 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-08-22 13:07:42 +0200 (Mon, 22 Aug 2016)");
  script_name('SSL/TLS: `preload` Missing in HSTS Header');
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_hsts_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("hsts/preload/missing/port");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#hsts");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc6797");
  script_xref(name:"URL", value:"https://hstspreload.appspot.com/");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"The remote HTTPS Server is missing the 'preload' attribute in the HSTS header.");

  script_tag(name:"solution", value:"Submit the domain to the 'HSTS preload list' and add the 'preload' attribute to the HSTS header.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if( ! port = get_kb_item( "hsts/preload/missing/port" ) ) exit( 0 );

banner = get_kb_item( "hsts/" + port + "/banner");

log_message( port:port, data:'The remote HTTPS Server is missing the "includeSubDomains" attribute in the HSTS header.\n\nHSTS Header:\n\n' + banner );
exit( 0 );
