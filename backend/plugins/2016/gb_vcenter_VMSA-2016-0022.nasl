###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2016-0022.nasl 11607 2018-09-25 13:53:15Z asteins $
#
# VMSA-2016-0022: XML External Entity (XXE) Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.140078");
  script_cve_id("CVE-2016-7458", "CVE-2016-7459", "CVE-2016-7460");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_version("$Revision: 11607 $");
  script_name("VMSA-2016-0022: XML External Entity (XXE) Vulnerability");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0022.html");

  script_tag(name:"vuldetect", value:"Check the build number");

  script_tag(name:"insight", value:"A specially crafted XML request issued to the server by an  authorized user may lead to unintended information disclosure.");

  script_tag(name:"solution", value:"Update to 6.0U2a/5.5U3e");

  script_tag(name:"summary", value:"vCenter Server contains an XML External Entity (XXE) vulnerability in the Log Browser, the Distributed Switch setup, and the Content Library.");

  script_tag(name:"affected", value:"vCenter Server 6.0/5.5");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-09-25 15:53:15 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-11-23 10:16:32 +0100 (Wed, 23 Nov 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

 exit(0);

}
include("vmware_esx.inc");
include("version_func.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

if( vcenter_version == "6.0.0" )
  if ( int( vcenter_build ) < int( 4541947 ) ) fix = '6.0 U2a)';

if( vcenter_version == "5.5.0" )
  if ( int( vcenter_build ) < int( 4180646 ) ) fix = '5.5 U3e';

if( fix )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build:fix, typ:'vCenter' ) );
  exit(0);
}

exit(99);

