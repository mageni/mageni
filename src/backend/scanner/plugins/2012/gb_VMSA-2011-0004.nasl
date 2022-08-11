###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2011-0004.nasl 11748 2018-10-04 10:12:39Z cfischer $
#
# VMSA-2011-0004.3 VMware ESX/ESXi SLPD denial of service vulnerability and ESX third party updates for Service Console packages bind, pam, and rpm.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103453");
  script_cve_id("CVE-2010-3613", "CVE-2010-3614", "CVE-2010-3762", "CVE-2010-3316", "CVE-2010-3435", "CVE-2010-3853", "CVE-2010-2059", "CVE-2010-3609");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11748 $");
  script_name("VMSA-2011-0004.3 VMware ESX/ESXi SLPD denial of service vulnerability and ESX third party updates for Service Console packages bind, pam, and rpm.");
  script_tag(name:"last_modification", value:"$Date: 2018-10-04 12:12:39 +0200 (Thu, 04 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-16 10:51:14 +0100 (Fri, 16 Mar 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0004.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2011-0004.3.");

  script_tag(name:"affected", value:"VMware ESXi 4.1 without patch ESXi410-201101201-SG.

  VMware ESXi 4.0 without patch ESXi400-201103401-SG.

  VMware ESX 4.1 without patches ESX410-201101201-SG, ESX410-201104407-SG and ESX410-201110207-SG.

  VMware ESX 4.0 without patches ESX400-201103401-SG, ESX400-201103404-SG, ESX400-201103406-SG and ESX400-201103407-SG.");

  script_tag(name:"impact", value:"a. Service Location Protocol daemon DoS

  Exploitation of this vulnerability could cause SLPD to consume significant CPU resources.");

  script_tag(name:"insight", value:"Service Location Protocol daemon (SLPD) denial of service issue and ESX 4.0 Service Console OS (COS) updates
  for bind, pam, and rpm.

  a. Service Location Protocol daemon DoS

  This patch fixes a denial-of-service vulnerability in the Service Location Protocol daemon (SLPD).

  b. Service Console update for bind

  This patch updates the bind-libs and bind-utils RPMs to version 9.3.6-4.P1.el5_5.3, which resolves multiple security
  issues.

  c. Service Console update for pam

  This patch updates the pam RPM to pam_0.99.6.2-3.27.5437.vmw, which resolves multiple security issues with PAM modules.

  d. Service Console update for rpm, rpm-libs, rpm-python, and popt

  This patch updates rpm, rpm-libs, and rpm-python RPMs to 4.4.2.3-20.el5_5.1, and popt to version 1.10.2.3-20.el5_5.1, which
  resolves a security issue.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc"); # Used in _esxi_patch_missing()
include("vmware_esx.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201101201-SG",
                     "4.0.0","ESXi400-201103401-SG");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);