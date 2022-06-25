###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA_NSX_2015-0003.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# VMSA-2015-0003: VMware NSX updates address critical information disclosure issue in JRE
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105424");
  script_cve_id("CVE-2014-6593");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 12083 $");
  script_name("VMSA-2015-0003: VMware NSX updates address critical information disclosure issue in JRE");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2015-0003.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version/build is present on the target host.");

  script_tag(name:"insight", value:"Oracle JRE is updated in VMware products to address a critical security issue that existed in earlier releases of Oracle JRE.");

  script_tag(name:"solution", value:"Apply the missing update.");

  script_tag(name:"summary", value:"VMware NSX updates address critical information disclosure issue in JRE.");

  script_tag(name:"affected", value:"NSX for vSphere prior 6.1.4 Build 2691049
NSX for Multi-Hypervisor prior to 4.2.4 Build 42965");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-27 17:31:18 +0100 (Tue, 27 Oct 2015)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_nsx_version.nasl");
  script_mandatory_keys("vmware_nsx/version");

 exit(0);

}

include("host_details.inc");
include("version_func.inc");

cpe = 'cpe:/a:vmware:nsx';

if( ! version = get_app_version( cpe:cpe ) ) exit( 0 );
if( ! build = get_kb_item("vmware_nsx/build") ) exit( 0 );

if( version_in_range( version:version, test_version:"4.2", test_version2:"4.2.3" ) )
  fix = '4.2.4-42965';

if( version =~ '^4\\.2\\.4' )
{
  if( int( build ) < int( 42965 ) )
    fix = '4.2.4-42965';
}

if( version_in_range( version:version, test_version:"6.1", test_version2:"6.1.3" ) )
  fix = '6.1.4-2691049';

if( version =~ '^6\\.1\\.4' )
{
  if( int( build ) < int( 2691049 ) )
    fix = '6.1.4-2691049';
}

if( fix )
{
  report = 'Installed version: ' + version + '-' + build + '\n' +
           'Fixed version:     ' + fix;

  security_message( port:0, data:report );
  exit( 0 );

}

exit(99);
