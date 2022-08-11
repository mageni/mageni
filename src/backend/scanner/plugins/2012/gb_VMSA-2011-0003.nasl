###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2011-0003.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2011-0003.2 Third party component updates for VMware vCenter Server, vCenter Update Manager, ESXi and ESX
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
  script_oid("1.3.6.1.4.1.25623.1.0.103454");
  script_cve_id("CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902", "CVE-2009-3548", "CVE-2010-2227", "CVE-2010-1157", "CVE-2010-2928", "CVE-2010-0734", "CVE-2010-1084", "CVE-2010-2066", "CVE-2010-2070", "CVE-2010-2226", "CVE-2010-2248", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-0008", "CVE-2010-0415", "CVE-2010-0437", "CVE-2009-4308", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0307", "CVE-2010-1086", "CVE-2010-0410", "CVE-2010-0730", "CVE-2010-1085", "CVE-2010-0291", "CVE-2010-0622", "CVE-2010-1087", "CVE-2010-1173", "CVE-2010-1437", "CVE-2010-1088", "CVE-2010-1187", "CVE-2010-1436", "CVE-2010-1641", "CVE-2010-3081", "CVE-2010-2240", "CVE-2008-5416", "CVE-2008-0085", "CVE-2008-0086", "CVE-2008-0107", "CVE-2008-0106", "CVE-2010-0740", "CVE-2010-0433", "CVE-2010-3864", "CVE-2010-2939", "CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839", "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843", "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847", "CVE-2010-0848", "CVE-2010-0849", "CVE-2010-0850", "CVE-2010-0886", "CVE-2010-3556", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3550", "CVE-2010-3561", "CVE-2010-3573", "CVE-2010-3565", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-1321", "CVE-2010-3548", "CVE-2010-3551", "CVE-2010-3562", "CVE-2010-3571", "CVE-2010-3554", "CVE-2010-3559", "CVE-2010-3572", "CVE-2010-3553", "CVE-2010-3549", "CVE-2010-3557", "CVE-2010-3541", "CVE-2010-3574", "CVE-2008-3825", "CVE-2009-1384");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2011-0003.2 Third party component updates for VMware vCenter Server, vCenter Update Manager, ESXi and ESX");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-16 11:19:42 +0100 (Fri, 16 Mar 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2011-0003.html");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2011-0003.2.");

  script_tag(name:"affected", value:"vCenter Server 4.1 without Update 1,

  vCenter Server 4.0 without Update 3,

  vCenter Update Manager 4.1 without Update 1,

  vCenter Update Manager 4.0 without Update 3,

  ESXi 4.1 without patch ESXi410-201101201-SG,

  ESXi 4.0 without patch ESXi400-201103401-SG.

  ESX 4.1 without patch ESX410-201101201-SG.

  ESX 4.0 without patches ESX400-201103401-SG, ESX400-201103403-SG.");

  script_tag(name:"insight", value:"Update 1 for vCenter Server 4.x, vCenter Update Manager 4.x, vSphere  Hypervisor (ESXi) 4.1, ESXi 4.1,
  addresses several security issues:

  a. vCenter Server and vCenter Update Manager update Microsoft SQL Server 2005 Express Edition to Service Pack 3

  Microsoft SQL Server 2005 Express Edition (SQL Express) distributed with vCenter Server 4.1 Update 1 and vCenter
  Update Manager 4.1 Update 1 is upgraded from  SQL Express Service Pack 2 to SQL Express Service Pack 3, to address
  multiple security issues that exist in the earlier releases of Microsoft SQL Express. Customers using other database
  solutions need not update for these issues.

  b. vCenter Apache Tomcat Management Application Credential Disclosure

  The Apache Tomcat Manager application configuration file contains logon credentials that can be read by unprivileged local
  users. The issue is resolved by removing the Manager application in vCenter 4.1 Update 1. If vCenter 4.1 is updated to vCenter
  4.1 Update 1 the logon credentials are not present in the configuration file after the update.

  c. vCenter Server and ESX, Oracle (Sun) JRE is updated to version 1.6.0_21

  Oracle (Sun) JRE update to version 1.6.0_21, which addresses multiple security issues that existed in earlier releases of
  Oracle (Sun) JRE.

  d. vCenter Update Manager Oracle (Sun) JRE is updated to version 1.5.0_26

  Oracle (Sun) JRE update to version 1.5.0_26, which addresses multiple security issues that existed in earlier releases of
  Oracle (Sun) JRE.

  e. vCenter Server and ESX Apache Tomcat updated to version 6.0.28

  Apache Tomcat updated to version 6.0.28, which addresses multiple security issues that existed in earlier releases of Apache
  Tomcat

  f. vCenter Server third party component OpenSSL updated to version 0.9.8n

  The version of the OpenSSL library in vCenter Server is updated to 0.9.8n.

  g. ESX third party component OpenSSL updated to version 0.9.8p

  The version of the ESX OpenSSL library is updated to 0.9.8p.

  h. ESXi third party component cURL updated

  The version of cURL library in ESXi is updated.

  i. ESX third party component pam_krb5 updated

  The version of pam_krb5 library is updated.

  j. ESX third party update for Service Console kernel

  The Service Console kernel is updated to include kernel version 2.6.18-194.11.1.");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

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