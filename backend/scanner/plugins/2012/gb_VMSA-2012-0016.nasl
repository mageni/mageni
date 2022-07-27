###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0016.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2012-0016: VMware security updates for vSphere API and ESX Service Console
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103609");
  script_cve_id("CVE-2012-5703", "CVE-2012-1033", "CVE-2012-1667", "CVE-2012-3817", "CVE-2011-4940", "CVE-2011-4944", "CVE-2012-1150", "CVE-2012-0876", "CVE-2012-1148", "CVE-2012-0441");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2012-0016: VMware security updates for vSphere API and ESX Service Console");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-11-16 11:02:01 +0100 (Fri, 16 Nov 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0016.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0016.");

  script_tag(name:"affected", value:"VMware ESXi 4.1 without patch ESXi410-201211401-SG

  VMware ESX 4.1 without patches ESX410-201211401-SG, ESX410-201211402-SG, ESX410-201211405-SG, and ESX410-201211407-SG");

  script_tag(name:"insight", value:"VMware has updated the vSphere API to address a denial of service vulnerability
  in ESX and ESXi. VMware has also updated the ESX Service Console to include several open source security updates.

  a. VMware vSphere API denial of service vulnerability

  The VMware vSphere API contains a denial of service vulnerability. This issue
  allows an unauthenticated user to send a maliciously crafted API request and
  disable the host daemon. Exploitation of the issue would prevent management
  activities on the host but any virtual machines running on the host would be
  unaffected.

  b. VMware vSphere API denial of service vulnerability

  The ESX service console bind packages are updated to the following versions:

  bind-libs-9.3.6-20.P1.el5_8.2

  bind-utils-9.3.6-20.P1.el5_8.2

  These updates fix multiple security issues.

  c. Update to ESX service console python packages

  The ESX service console Python packages are updated to the following versions:

   python-2.4.3-46.el5_8.2.x86_64

   python-libs-2.4.3-46.el5_8.2.x86_64

  These updates fix multiple security issues.

  d. Update to ESX service console expat package

  The ESX service console expat package is updated to expat-1.95.8-11.el5_8.

  This update fixes multiple security issues.

  e. Update to ESX service console nspr and nss packages

  This patch updates the ESX service console Netscape Portable Runtime and
  Network Security Services RPMs to versions nspr-4.9.1.4.el5_8 and
  nss-3.13.5.4.9834, respectively, to resolve multiple security issues.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201211401-SG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);