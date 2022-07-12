###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vcenter_VMSA-2013-0012.nasl 11108 2018-08-24 14:27:07Z mmartin $
#
# VMware Security Updates for vCenter Server (VMSA-2013-0012)
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
  script_oid("1.3.6.1.4.1.25623.1.0.103871");
  script_cve_id("CVE-2013-5971");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11108 $");
  script_name("VMware Security Updates for vCenter Server (VMSA-2013-0012)");


  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0012.html");
  script_xref(name:"URL", value:"https://www.vmware.com/support/vsphere5/doc/vsp_vc50_u3_rel_notes.html");

  script_tag(name:"last_modification", value:"$Date: 2018-08-24 16:27:07 +0200 (Fri, 24 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-01-09 11:04:01 +0100 (Thu, 09 Jan 2014)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_vcenter_detect.nasl");
  script_mandatory_keys("VMware_vCenter/version", "VMware_vCenter/build");

  script_tag(name:"vuldetect", value:"Check the build number.");
  script_tag(name:"insight", value:"vCenter and Update Manager, Oracle JRE update 1.6.0_51.

Oracle JRE is updated to version 1.6.0_51, which addresses
multiple security issues that existed in earlier releases of
Oracle JRE.

Oracle has documented the CVE identifiers that are addressed
in JRE 1.6.0_51 in the Oracle Java SE Critical Patch Update
Advisory of June 2013. The References section provides a
link to this advisory.");
  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"VMware has updated vCenter Server to address multiple security
vulnerabilities.");
  script_tag(name:"affected", value:"VMware vCenter Server before 5.0 update 3");

 exit(0);

}

include("vmware_esx.inc");

if ( ! vcenter_version = get_kb_item("VMware_vCenter/version"))exit(0);
if ( ! vcenter_build = get_kb_item("VMware_vCenter/build"))exit(0);

fixed_builds = make_array("5.0.0","1300600",
                          "5.1.0","1474365");

if ( ! fixed_builds[ vcenter_version] ) exit( 0 );

if ( int( vcenter_build ) < int( fixed_builds[ vcenter_version ] ) )
{
  security_message( port:0, data: esxi_remote_report( ver:vcenter_version, build: vcenter_build, fixed_build: fixed_builds[vcenter_version], typ:'vCenter' ) );
  exit(0);
}

exit(99);

