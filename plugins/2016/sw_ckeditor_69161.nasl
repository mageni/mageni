###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_ckeditor_69161.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# CKEditor Preview Plugin Unspecified Cross Site Scripting Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH
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

CPE = "cpe:/a:ckeditor:ckeditor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111095");
  script_version("$Revision: 11961 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-17 18:00:00 +0200 (Sun, 17 Apr 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_bugtraq_id(69161);
  script_name("CKEditor Preview Plugin Unspecified Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_ckeditor_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ckeditor/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69161");
  script_xref(name:"URL", value:"http://ckeditor.com/release/CKEditor-4.4.3");

  script_tag(name:"summary", value:"Preview plugin for CKEditor is prone to a unspecified cross-site scripting
  vulnerability because it fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in the
  browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal
  cookie-based authentication credentials and launch other attacks.");
  script_tag(name:"affected", value:"Versions prior to CKEditor 4.4.3 are vulnerable.");
  script_tag(name:"solution", value:"Update to CKEditor Version 4.4.3 or later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); #Preview plugin might have been removed / not installed

  script_xref(name:"URL", value:"http://ckeditor.com/download");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.4.3" ) ) {

  report = report_fixed_ver( installed_version:vers, fixed_version:"4.4.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
