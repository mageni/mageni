###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2011-0007.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2011-0007 VMware ESXi and ESX Denial of Service and third party updates for Likewise components and ESX Service Console
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
  script_oid("1.3.6.1.4.1.25623.1.0.103450");
  script_cve_id("CVE-2011-1785", "CVE-2011-1786", "CVE-2010-1324", "CVE-2010-1323", "CVE-2010-4020", "CVE-2010-4021", "CVE-2010-2240");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2011-0007 VMware ESXi and ESX Denial of Service and third party updates for Likewise components and ESX Service Console");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-15 17:23:21 +0100 (Thu, 15 Mar 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0007.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2011-0007.");

  script_tag(name:"affected", value:"VMware ESXi 4.1 without patch ESXi410-201104401-SG.

  VMware ESXi 4.0 without patch ESXi400-201104401-SG.

  VMware ESX 4.1 without patch ESX410-201104401-SG.

  VMware ESX 4.0 without patch ESX400-201104401-SG.");

  script_tag(name:"insight", value:"VMware ESXi and ESX could encounter a socket exhaustion situation which may lead to
  a denial of service. Updates to Likewise components and to the ESX Service Console address security vulnerabilities.

  a. ESX/ESXi Socket Exhaustion

  By sending malicious network traffic to an ESXi or ESX host an attacker could
  exhaust the available sockets which would prevent further connections to the
  host. In the event a host becomes inaccessible its virtual machines will
  continue to run and have network connectivity but a reboot of the ESXi or ESX
  host may be required in order to be able to connect to the host again.

  ESXi and ESX hosts may intermittently lose connectivity caused by applications
  that do not correctly close sockets. If this occurs an error message similar to
  the following may be written to the vpxa log:

  socket() returns -1 (Cannot allocate memory)

  An error message similar to the following may be written to the vmkernel logs:

  socreate(type=2, proto=17) failed with error 55

  b. Likewise package update

  Updates to the vmware-esx-likewise-openldap and vmware-esx-likewise-krb5
  packages address several security issues.

  One of the vulnerabilities is specific to Likewise while the other
  vulnerabilities are present in the MIT version of krb5. An incorrect assert()
  call in Likewise may lead to a termination of the Likewise-open lsassd service
  if a username with an illegal byte sequence is entered for user authentication
  when logging in to the Active Directory domain of the ESXi/ESX host. This would
  lead to a denial of service. The MIT-krb5 vulnerabilities are detailed in
  MITKRB5-SA-2010-007.

  c. ESX third party update for Service Console kernel

  The Service Console kernel is updated to include a fix for a security issue.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc"); # Used in _esxi_patch_missing()
include("vmware_esx.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-201104401-SG",
                     "4.0.0","ESXi400-201104401-SG");


if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);