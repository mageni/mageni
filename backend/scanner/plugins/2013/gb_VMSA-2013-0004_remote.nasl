###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2013-0004_remote.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# VMSA-2013-0004 VMware ESXi security update for third party library (remote check)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103848");
  script_cve_id("CVE-2012-5134");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11865 $");
  script_name("VMSA-2013-0004 VMware ESXi security update for third party library (remote check)");


  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-12-03 14:03:01 +0100 (Tue, 03 Dec 2013)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl");
  script_mandatory_keys("VMware/ESX/build", "VMware/ESX/version");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates
from VMSA-2013-0004.");
  script_tag(name:"vuldetect", value:"Check the build number.");
  script_tag(name:"insight", value:"The ESXi userworld libxml2 library has been updated to resolve a security issue.");
  script_tag(name:"solution", value:"Apply the missing patch(es).");
  script_tag(name:"affected", value:"ESXi 5.1 without patch ESXi510-201304101
ESXi 5.0 without patch ESXi500-201303101
ESXi 4.0 without patch ESXi400-201305001
ESXi 4.1 without patch ESXi410-201304401");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2013-0004.html");
  exit(0);
}

include("vmware_esx.inc");

if(!esxVersion = get_kb_item("VMware/ESX/version"))exit(0);
if(!esxBuild = get_kb_item("VMware/ESX/build"))exit(0);

fixed_builds = make_array("5.0.0","1022489",
                          "5.1.0","1063671");

if(!fixed_builds[esxVersion])exit(0);

if(int(esxBuild) < int(fixed_builds[esxVersion])) {

  security_message(port:0, data: esxi_remote_report(ver:esxVersion, build: esxBuild, fixed_build: fixed_builds[esxVersion]));
  exit(0);
}

exit(99);
