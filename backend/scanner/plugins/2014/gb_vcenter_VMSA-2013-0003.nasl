###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2013-0003.nasl 14231 2019-03-16 10:56:51Z mmartin $
#
# VMware Security Updates for vCenter Server (VMSA-2013-0003)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103874");
  script_cve_id("CVE-2013-1659");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14231 $");
  script_name("VMware Security Updates for vCenter Server (VMSA-2013-0003)");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0003.html");

  script_tag(name:"last_modification", value:"$Date: 2019-03-16 11:56:51 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-09 13:04:01 +0100 (Thu, 09 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

  script_tag(name:"vuldetect", value:"Check the build number.");
  script_tag(name:"insight", value:"VMware vCenter, ESXi and ESX NFC protocol memory corruption vulnerability

VMware vCenter Server, ESXi and ESX contain a vulnerability in the
handling of the Network File Copy (NFC) protocol. To exploit this
vulnerability, an attacker must intercept and modify the NFC traffic
between vCenter Server and the client or ESXi/ESX and the client.
Exploitation of the issue may lead to code execution.

To reduce the likelihood of exploitation, vSphere components should be
deployed on an isolated management network.");
  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"VMware has updated VMware vCenter Server to address a vulnerability
in the Network File Copy (NFC) Protocol.");
  script_tag(name:"affected", value:"VMware vCenter Server 5.1 prior to 5.1.0b
VMware vCenter Server 5.0 prior to 5.0 Update 2");

  exit(0);
}

include("vmware_esx.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version"))exit(0);
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build"))exit(0);

fixed_builds = make_array("5.0.0","913577",
                          "5.1.0","947673");

if ( ! fixed_builds[ vcenter_version] ) exit( 0 );

if ( int( vcenter_build ) < int( fixed_builds[ vcenter_version ] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build: fixed_builds[vcenter_version], typ:'vCenter' ) );
  exit(0);
}

exit(99);