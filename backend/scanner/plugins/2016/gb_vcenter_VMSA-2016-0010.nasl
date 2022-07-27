###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2016-0010.nasl 11640 2018-09-27 07:15:20Z asteins $
#
# VMSA-2016-0010 (vCenter) VMware product updates address multiple important security issues
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105848");
  script_cve_id("CVE-2016-5331");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 11640 $");
  script_name("VMSA-2016-0010 (vCenter) VMware product updates address multiple important security issues");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0010.html");

  script_tag(name:"vuldetect", value:"Check the build number");
  script_tag(name:"solution", value:"Update to 6.0 U2 or newer");

  script_tag(name:"summary", value:"vCenter Server contain an HTTP header injection vulnerability due to lack of input validation. An attacker can exploit this issue
to set arbitrary HTTP response headers and cookies, which may allow for cross-site scripting and malicious redirect attacks.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-09-27 09:15:20 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-05 15:46:04 +0200 (Fri, 05 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

 exit(0);

}
include("vmware_esx.inc");
include("version_func.inc");
include("host_details.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

if( vcenter_version == "6.0.0" )
  if ( int( vcenter_build ) < int( 3634788 ) ) fix = '6.0 U2 (Build 3634788)';

if( fix )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build:fix, typ:'vCenter' ) );
  exit(0);
}

exit(99);

