###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kentico_cms_xss_vuln.nasl 9192 2018-03-23 14:54:27Z cfischer $
#
# Kentico CMS 9-11 XSS Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113118");
  script_version("$Revision: 9192 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-23 15:54:27 +0100 (Fri, 23 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 14:34:43 +0100 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2018-7205");

  script_name("Kentico CMS 9-11 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kentico_cms_detect.nasl");
  script_mandatory_keys("kentico_cms/detected");

  script_tag(name:"summary", value:"Kentico CMS is prone to an XSS Vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:'1 Log in as administrator.

  2 Go to "Pages".

  3 At "Edit" on left panel, select any page under site.

  4 Click "Template" tab locate on top right panel.

  5 Under "Template" tab, select "Edit template properties".

  6 Select "Device layout".

  7 Select "Create device layout".

  8 At popped "New device layout" select device on drop-down list and save.

  9 Edit created device layout, select "Design".

  10 Inject \')};alert(\'xss\');// into \"devicename\" parameter.
  ');
  script_tag(name:"affected", value:"Kentico CMS versions 9 through 11.");
  script_tag(name:"solution", value:"No solution available as of 20th February 2018. Information will be updated once a fix becomes available.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/541792");
  script_xref(name:"URL", value:"https://devnet.kentico.com/download/hotfixes");

  exit( 0 );
}

CPE = "cpe:/a:kentico:cms";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_in_range( version: version, test_version: "9.0.0", test_version2:"11.0.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "NoneAvailable" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
