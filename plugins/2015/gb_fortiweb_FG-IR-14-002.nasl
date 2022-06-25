###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortiweb_FG-IR-14-002.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# FortiOS: FortiWeb Cross-Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:fortinet:fortiweb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105206");
  script_cve_id("CVE-2013-7181");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12106 $");

  script_name("FortiOS: FortiWeb Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-14-002");

  script_tag(name:"impact", value:"A remote unauthenticated attacker may be able to execute arbitrary script in the context of the end-user's browser session.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to FortiWeb 5.1.0 or higher.");

  script_tag(name:"summary", value:"Fortiweb 5.0.3 and earlier versions contain a cross-site scripting vulnerability. The filter parameter in the URL '/user/ldap_user/add'
is vulnerable to cross-site scripting attack.");

  script_tag(name:"affected", value:"FortiWeb 5.0.3 and lower.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-11 12:17:13 +0100 (Wed, 11 Feb 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_fortiweb_version.nasl");
  script_mandatory_keys("fortiweb/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

version = get_app_version( cpe:CPE );
if( ! version )
  version = get_kb_item("fortiweb/version");

if( ! version ) exit( 0 );

fix = "5.1.0";

if( version_is_less( version:version, test_version:fix ) )
{
  model = get_kb_item("fortiweb/model");
  if( ! isnull( model ) ) report = 'Model:             ' + model + '\n';
  report += 'Installed Version: ' + version + '\nFixed Version:     ' + fix + '\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

