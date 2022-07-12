###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0005.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2012-0005 VMware vCenter Server, Orchestrator, Update Manager, vShield, vSphere Client, ESXi and ESX address several security issues
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
  script_oid("1.3.6.1.4.1.25623.1.0.103457");
  script_cve_id("CVE-2012-1508", "CVE-2012-1509", "CVE-2012-1510", "CVE-2012-1512", "CVE-2012-1513", "CVE-2012-1514", "CVE-2011-3190", "CVE-2011-3375", "CVE-2012-0022", "CVE-2010-0405");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2012-0005 VMware vCenter Server, Orchestrator, Update Manager, vShield, vSphere Client, ESXi and ESX address several security issues");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-16 16:53:01 +0100 (Fri, 16 Mar 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0005.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0005.");

  script_tag(name:"affected", value:"VMware vCenter Server 5.0

  VMware vSphere Client 5.0

  VMware vSphere Client 4.1 Update 1 and earlier

  VMware vCenter Orchestrator 4.2

  VMware vCenter Orchestrator 4.1 Update 1 and earlier

  VMware vCenter Orchestrator 4.0 Update 3 and earlier

  VMware vShield Manager 4.1 Update 1

  VMware vShield Manager 1.0 Update 1

  VMware Update Manager 5.0

  ESXi 5.0 without patches ESXi500-201203101-SG, ESXi500-201112402-BG

  ESXi 4.1 without patch ESXi410-201110202-UG

  ESXi 4.0 without patch ESXi400-201110402-BG

  ESX 4.1 without patch ESX410-201110201-SG

  ESX 4.0 without patch ESX400-201110401-SG");

  script_tag(name:"insight", value:"VMware vCenter Server, Orchestrator, Update Manager, vShield, vSphere Client, ESXi and ESX address
  several security issues:

  a. VMware Tools Display Driver Privilege Escalation

  The VMware XPDM and WDDM display drivers contain buffer overflow vulnerabilities and the XPDM display
  driver does not properly check for NULL pointers. Exploitation of these issues may lead to local privilege
  escalation on Windows-based Guest Operating Systems.

  b. vSphere Client internal browser input validation vulnerability

  The vSphere Client has an internal browser that renders html pages from log file entries. This browser doesn't
  properly sanitize input and may run script that is introduced into the log files. In order for the script to
  run, the user would need to open an individual, malicious log file entry. The script would run with the
  permissions of the user that runs the vSphere Client.

  c. vCenter Orchestrator Password Disclosure

  The vCenter Orchestrator (vCO) Web Configuration tool reflects back the vCenter Server password as part of the
  webpage. This might allow the logged-in vCO administrator to retrieve the vCenter Server password.

  d. vShield Manager Cross-Site Request Forgery vulnerability

  The vShield Manager (vSM) interface has a Cross-Site Request Forgery vulnerability. If an attacker can convince
  an authenticated user to visit a malicious link, the attacker may force the victim to forward an authenticated
  request to the server.

  e. vCenter Update Manager, Oracle (Sun) JRE update 1.6.0_30

  Oracle (Sun) JRE is updated to version 1.6.0_30, which addresses multiple security issues that existed in earlier
  releases of Oracle (Sun) JRE.

  f. vCenter Server Apache Tomcat update 6.0.35

  Apache Tomcat has been updated to version 6.0.35 to address multiple security issues.

  g. ESXi update to third party component bzip2

  The bzip2 library is updated to version 1.0.6, which resolves a security issue.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.0.0", "ESXi400-201110402-BG",
                     "4.1.0", "ESXi410-201110202-UG",
                     "5.0.0", "VIB:esx-base:5.0.0-0.10.608089");


if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);