###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_198_lin.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# MoinMoin < 1.9.8 Cross-Site Scripting Vulnerability (Linux)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108328");
  script_version("$Revision: 12120 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-12 10:47:19 +0100 (Mon, 12 Feb 2018)");
  script_name("MoinMoin < 1.9.8 Cross-Site Scripting Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("moinmoinWiki/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"http://hg.moinmo.in/moin/1.9/rev/7dd392e803fa");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may help the attacker steal cookie-based authentication
  credentials and launch other attacks.");
  script_tag(name:"affected", value:"MoinMoin 1.9.7 and prior are vulnerable.");
  script_tag(name:"solution", value:"Update to version 1.9.8 or later. Please see the references for
  more information.");
  script_tag(name:"summary", value:"MoinMoin is prone to a cross-site scripting vulnerability because it
  fails to sufficiently sanitize user-supplied input data in useragent event stats.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.9.8" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.9.8" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );