###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2014-0006.nasl 11194 2018-09-03 12:44:14Z mmartin $
#
# VMware Security Updates for vCenter Server (VMSA-2014-0006)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105057");
  script_cve_id("CVE-2014-0224", "CVE-2014-0198", "CVE-2010-5298", "CVE-2014-3470");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11194 $");
  script_name("VMware Security Updates for vCenter Server (VMSA-2014-0006)");


  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2014-0006.html");

  script_tag(name:"last_modification", value:"$Date: 2018-09-03 14:44:14 +0200 (Mon, 03 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-07-04 11:04:01 +0100 (Fri, 04 Jul 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

  script_tag(name:"vuldetect", value:"Check the build number");
  script_tag(name:"insight", value:"a. OpenSSL update for multiple products.

OpenSSL libraries have been updated in multiple products to versions 0.9.8za and 1.0.1h
in order to resolve multiple security issues.");
  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"VMware product updates address OpenSSL security vulnerabilities.");
  script_tag(name:"affected", value:"vCenter prior to 5.5u1b
vCenter prior to 5.1U2a
vCenter prior to 5.0U3a");

 exit(0);

}

include("vmware_esx.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version") ) exit( 0 );
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build") ) exit( 0 );

fixed_builds = make_array( "5.5.0","1891310",
                           "5.1.0","1917403",
                           "5.0.0","1923446" );

if ( ! fixed_builds[ vcenter_version] ) exit( 0 );

if ( int( vcenter_build ) < int( fixed_builds[ vcenter_version ] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build: fixed_builds[vcenter_version], typ:'vCenter' ) );
  exit(0);
}

exit(99);
