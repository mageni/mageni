###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_vaadin_57667.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Vaadin Framework 'JsonPaintTarget.addAttribute()' HTML Injection Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = 'cpe:/a:vaadin:vaadin';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105180");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-22 12:00:00 +0100 (Thu, 22 Jan 2015)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_bugtraq_id(57667);

  script_name("Vaadin Framework 'JsonPaintTarget.addAttribute()' HTML Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_vaadin_detect.nasl");
  script_require_ports("Services/www", 8888);
  script_mandatory_keys("vaadin/installed");

  script_tag(name:"summary", value:"This web application is running with the Vaadin Framework which
  is prone to a 'JsonPaintTarget.addAttribute()' HTML Injection vulnerability");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Vaadin Framework is prone to an HTML-injection vulnerability because
  it fails to properly sanitize user-supplied input.");
  script_tag(name:"impact", value:"Successful exploits will allow attacker-supplied HTML and script code
  to run in the context of the affected browser, potentially allowing the attacker to steal cookie-based
  authentication credentials or control how the site is rendered to the user. Other attacks are also possible.");
  script_tag(name:"affected", value:"Vaadin Framework versions from 6.0.0 up to 6.8.7");
  script_tag(name:"solution", value:"Upgrade to Vaadin Framework version 6.8.8 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57667");
  script_xref(name:"URL", value:"http://www.vaadin.com/download/release/6.8/6.8.8/release-notes.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.vaadin.com/releases");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.8.7" ) ) {

  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "6.8.8" + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
