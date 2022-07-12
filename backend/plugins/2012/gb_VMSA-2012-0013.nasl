###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA-2012-0013.nasl 11696 2018-09-28 21:16:43Z cfischer $
#
# VMSA-2012-0013 VMware vSphere and vCOps updates to third party libraries
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
  script_oid("1.3.6.1.4.1.25623.1.0.103558");
  script_cve_id("CVE-2010-4180", "CVE-2010-4252", "CVE-2011-0014", "CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2012-0050",
               "CVE-2012-2110", "CVE-2011-1833", "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-3188", "CVE-2011-3209", "CVE-2011-3363", "CVE-2011-4110", "CVE-2011-1020",
               "CVE-2011-4132", "CVE-2011-4324", "CVE-2011-4325", "CVE-2012-0207", "CVE-2011-2699", "CVE-2012-1583", "CVE-2010-2761", "CVE-2010-4410", "CVE-2011-3597",
               "CVE-2012-0841", "CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0830", "CVE-2011-1089", "CVE-2011-4609", "CVE-2012-0864", "CVE-2011-4128", "CVE-2012-1569",
               "CVE-2012-1573", "CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815", "CVE-2012-0393", "CVE-2012-0507");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11696 $");
  script_name("VMSA-2012-0013 VMware vSphere and vCOps updates to third party libraries.");
  script_tag(name:"last_modification", value:"$Date: 2018-09-28 23:16:43 +0200 (Fri, 28 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-08-31 11:02:01 +0100 (Fri, 31 Aug 2012)");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esxi_init.nasl");
  script_mandatory_keys("VMware/ESXi/LSC", "VMware/ESX/version");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2012-0013.html");

  script_tag(name:"solution", value:"Apply the missing patch(es).");

  script_tag(name:"summary", value:"The remote ESXi is missing one or more security related Updates from VMSA-2012-0013.");

  script_tag(name:"affected", value:"VMware vCenter 4.1 without Update 3

  VMware vCenter Update Manager 4.1 without Update 3

  VMware ESX without patches ESX410-201208101-SG, ESX410-201208102-SG, ESX410-201208103-SG, ESX410-201208104-SG, ESX410-201208105-SG, ESX410-201208106-SG, ESX410-201208107-SG

  VMware ESXi without patch ESXi410-201208101-SG");

  script_tag(name:"insight", value:"VMware has updated several third party libraries in vSphere and vcOps to address multiple security vulnerabilities.

  a. vCenter and ESX update to JRE 1.6.0 Update 31

  The Oracle (Sun) JRE is updated to version 1.6.0_31, which addresses multiple
  security issues. Oracle has documented the CVE identifiers that are addressed by
  this update in the Oracle Java SE Critical Patch Update Advisory of February 2012.

  b. vCenter Update Manager update to JRE 1.5.0 Update 36

  The Oracle (Sun) JRE is updated to 1.5.0_36 to address multiple security issues.
  Oracle has documented the CVE identifiers that are addressed in JRE 1.5.0_36 in
  the Oracle Java SE Critical Patch Update Advisory for June 2012.

  c. Update to ESX/ESXi userworld OpenSSL library

  The ESX/ESXi userworld OpenSSL library is updated from version 0.9.8p to version
  0.9.8t to resolve multiple security issues.

  d. Update to ESX service console OpenSSL RPM

  The service console OpenSSL RPM is updated to version 0.9.8e-22.el5_8.3 to
  resolve a security issue.

  e. Update to ESX service console kernel

  The ESX service console kernel is updated to resolve multiple security issues.

  f. Update to ESX service console Perl RPM

  The ESX service console Perl RPM is updated to perl-5.8.8.32.1.8999.vmw to
  resolve multiple security issues.

  g. Update to ESX service console libxml2 RPM

  The ESX service console libmxl2 RPMs are updated to
  libxml2-2.6.26-2.1.15.el5_8.2 and libxml2-python-2.6.26-2.1.15.el5_8.2 to
  resolve a security issue.

  h. Update to ESX service console glibc RPM

  The ESX service console glibc RPM is updated to version glibc-2.5-81.el5_8.1 to
  resolve multiple security issues.

  i. Update to ESX service console GnuTLS RPM

  The ESX service console GnuTLS RPM is updated to version 1.4.1-7.el5_8.2 to
  resolve multiple security issues.

  j. Update to ESX service console popt, rpm, rpm-libs, and rpm-python RPMS

  The ESX service console popt, rpm, rpm-libs, and rpm-python RPMS are updated to
  the following versions to resolve multiple security issues:

  k. Vulnerability in third party Apache Struts component

  The version of Apache Struts in vCenter Operations has been updated to 2.3.4
  which addresses an arbitrary file overwrite vulnerability. This vulnerability
  allows an attacker to create a denial of service by overwriting arbitrary files
  without authentication. The attacker would need to be on the same network as the
  system where vCOps is installed.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("vmware_esx.inc");
include("version_func.inc");

if(!get_kb_item('VMware/ESXi/LSC'))exit(0);
if(! esxVersion = get_kb_item("VMware/ESX/version"))exit(0);

patches = make_array("4.1.0","ESXi410-Update03:2012-08-30");

if(!patches[esxVersion])exit(0);

if(_esxi_patch_missing(esxi_version:esxVersion, patch:patches[esxVersion])) {
  security_message(port:0);
  exit(0);
}

exit(99);