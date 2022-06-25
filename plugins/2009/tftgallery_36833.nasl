###############################################################################
# OpenVAS Vulnerability Test
# $Id: tftgallery_36833.nasl 12315 2018-11-12 09:24:01Z cfischer $
#
# TFTgallery 'album' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:tftgallery:tftgallery";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100325");
  script_version("$Revision: 12315 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-12 10:24:01 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
  script_cve_id("CVE-2009-3833");
  script_bugtraq_id(36833);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("TFTgallery 'album' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("tftgallery_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("tftgallery/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36833");
  script_xref(name:"URL", value:"http://www.tftgallery.org/");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected
  site. This may let the attacker steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"This issue affects TFTgallery 0.13. Other versions may be
  vulnerable as well.");

  script_tag(name:"summary", value:"TFTgallery is prone to a cross-site scripting vulnerability because
  the application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"0.13" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix", install_path:path );
  security_message( port:port, data:report );
}

exit( 0 );