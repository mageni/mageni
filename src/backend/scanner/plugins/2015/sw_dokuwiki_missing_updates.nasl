###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_dokuwiki_missing_updates.nasl 10833 2018-08-08 10:35:26Z cfischer $
#
# Detection of missing Dokuwiki (security-)updates
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

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111043");
  script_version("$Revision: 10833 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 12:35:26 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2015-10-29 16:00:00 +0100 (Thu, 29 Oct 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Detection of missing Dokuwiki (security-)updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/missing_updates");

  script_tag(name:"summary", value:"Dokuwiki might show available and not applied (security-)updates to unauthenticated users.");

  script_tag(name:"vuldetect", value:"Check the notify banner shown to the user for missing (security-)updates.");

  script_tag(name:"impact", value:"Based on the information shown an attacker might be able to exploit known vulnerabilities
  found within this installation.");

  script_tag(name:"affected", value:"Not updated Dokuwiki versions.");

  script_tag(name:"solution", value:"The vendor has released updates at the referred URLs.");

  script_xref(name:"URL", value:"http://download.dokuwiki.org/");
  script_xref(name:"URL", value:"https://www.dokuwiki.org/changes");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! loc = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( get_kb_item( "dokuwiki/missing_updates/" + port + loc ) ) {
  report = report_vuln_url( port:port, url:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
