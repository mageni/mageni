###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortigate_FG-IR-16-050.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# FortiOS: Local Admin Password Hash Leak Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/h:fortinet:fortigate";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140156");
  script_cve_id("CVE-2016-7542");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("$Revision: 12106 $");

  script_name("FortiOS: Local Admin Password Hash Leak Vulnerability");

  script_xref(name:"URL", value:"http://fortiguard.com/advisory/FG-IR-16-050");

  script_tag(name:"impact", value:"A read-only administrator may have access to read-write administrators password hashes (not including super-admins) stored on the appliance via the webui REST API, and may therefore be able to crack them.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to 5.4.2 GA
Upgrade to 5.2.10 GA");

  script_tag(name:"summary", value:"FortiOS Local Admin Password Hash Leak Vulnerability");

  script_tag(name:"affected", value:"FortiOS 5.2.0 - 5.2.9, 5.4.1");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-09 13:57:20 +0100 (Thu, 09 Feb 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_fortigate_version.nasl");
  script_mandatory_keys("fortigate/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ "^5\.2" )
  fix = '5.2.10';
else if( version =~ "^5\.4" )
  fix = '5.4.2';

if( ! fix ) exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  model = get_kb_item("fortigate/model");
  if( ! isnull( model ) ) report = 'Model:             ' + model + '\n';
  report += 'Installed Version: ' + version + '\nFixed Version:     ' + fix + '\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

