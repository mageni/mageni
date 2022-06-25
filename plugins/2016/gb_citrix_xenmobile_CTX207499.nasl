###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_xenmobile_CTX207499.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Persistent Cross-Site Scripting Vulnerability in Citrix XenMobile Server 10.x Web User Interface
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:citrix:xenmobile_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105580");
  script_cve_id("CVE-2016-2789");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12051 $");

  script_name("Persistent Cross-Site Scripting Vulnerability in Citrix XenMobile Server 10.x Web User Interface");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX207499");

  script_tag(name:"impact", value:"This vulnerability could potentially be used to execute malicious client-side script in the same context as legitimate content from the web server, if this vulnerability is used to execute script in the browser of an authenticated administrator then the script may be able to gain access to the administrator's session or other potentially sensitive information.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Citrix XenMobile 10.3 Rolling Patch 1/Citrix XenMobile 10.1 Rolling Patch 4 or newer.");
  script_tag(name:"summary", value:"A Cross-Site Scripting (XSS) vulnerability has been identified in XenMobile Server 10.x.");
  script_tag(name:"affected", value:"All versions of Citrix XenMobile Server 10.0

Citrix XenMobile Server 10.1 earlier than Rolling Patch 4

Citrix XenMobile Server 10.3 earlier than Rolling Patch 1");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-18 11:15:00 +0100 (Fri, 18 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_citrix_xenmobile_detect.nasl");
  script_require_ports("Services/www", 80, 443, 8443);
  script_mandatory_keys("citrix_xenmobile_server/patch_release", "citrix_xenmobile_server/version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers =  get_app_version( cpe:CPE, port:port ) ) exit( 0 );

patch = get_kb_item( "citrix_xenmobile_server/patch_release" );

if( vers =~ "^10\.0" ) fix = '10.1 Rolling Patch 4';

if( vers =~ "^10\.1" )
{
  if( patch )
  {
    if( patch == 'no_patches' )
      fix = '10.1 Rolling Patch 4';
    else
      if(version_is_less( version:patch, test_version:"10.1.0.68170" ) ) fix = '10.1 Rolling Patch 4';
  }
}

if( vers =~ "^10\.3" )
{
  if( patch )
  {
    if( patch == 'no_patches' )
      fix = '10.3 Rolling Patch 1';
    else
      if(version_is_less( version:patch, test_version:"10.3.0.10004" ) ) fix = '10.3 Rolling Patch 1';
  }
}

if( fix )
{
    report = report_fixed_ver(  installed_version:vers, fixed_version:'none', installed_patch:patch, fixed_patch:fix );
    security_message( port:port, data:report );
    exit (0 );
}

exit( 99 );

