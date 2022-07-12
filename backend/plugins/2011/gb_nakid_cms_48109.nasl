###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nakid_cms_48109.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# Nakid CMS 'CKEditorFuncNum' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:jeffkilroy:nakid_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103176");
  script_version("$Revision: 12018 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-06-07 12:59:38 +0200 (Tue, 07 Jun 2011)");
  script_bugtraq_id(48109);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("Nakid CMS 'CKEditorFuncNum' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_nakid_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("NakidCMS/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/48109");
  script_xref(name:"URL", value:"http://www.nakid.org/");

  script_tag(name:"summary", value:"Nakid CMS is prone to a cross-site scripting vulnerability because it
  fails to sufficiently sanitize user-supplied data.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks.");
  script_tag(name:"affected", value:"Nakid CMS 1.0.2 is vulnerable. Other versions may also be affected.");
  script_tag(name:"solution", value:"Upgrade to the latest version.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/assets/addons/kcfinder/browse.php?CKEditorFuncNum=0);alert(/openvas-xss-test/);//";

if( http_vuln_check( port:port, url:url, pattern:"alert\(/openvas-xss-test/\)", check_header:TRUE ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
