###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1008_2.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# Ubuntu Update for virtinst update USN-1008-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

include("revisions-lib.inc");
tag_insight = "Libvirt in Ubuntu 10.04 LTS now no longer probes qemu disks for the image
  format and defaults to 'raw' when the format is not specified in the XML.
  This change in behavior breaks virt-install --import because virtinst in
  Ubuntu 10.04 LTS did not allow for specifying a disk format and does not
  specify a format in the XML. This update adds the 'format=' option when
  specifying a disk. For example, to import an existing VM which uses a qcow2
  disk format, use somthing like the following:

  For more information, see man 1 virt-install.
  
  Original advisory details:
  
  It was discovered that libvirt would probe disk backing stores without
  consulting the defined format for the disk. A privileged attacker in the
  guest could exploit this to read arbitrary files on the host. This issue
  only affected Ubuntu 10.04 LTS. By default, guests are confined by an
  AppArmor profile which provided partial protection against this flaw.
  (CVE-2010-2237, CVE-2010-2238)
  
  It was discovered that libvirt would create new VMs without setting a
  backing store format. A privileged attacker in the guest could exploit this
  to read arbitrary files on the host. This issue did not affect Ubuntu 8.04
  LTS. In Ubuntu 9.10 and later guests are confined by an AppArmor profile
  which provided partial protection against this flaw. (CVE-2010-2239)
  
  Jeremy Nickurak discovered that libvirt created iptables rules with too
  lenient mappings of source ports. A privileged attacker in the guest could
  bypass intended restrictions to access privileged resources on the host.
  (CVE-2010-2242)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1008-2";
tag_affected = "virtinst update on Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1008-2/");
  script_oid("1.3.6.1.4.1.25623.1.0.313541");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-22 16:42:09 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_cve_id("CVE-2010-2237", "CVE-2010-2238", "CVE-2010-2239", "CVE-2010-2242");
  script_name("Ubuntu Update for virtinst update USN-1008-2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python-virtinst", ver:"0.500.1-2ubuntu6.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"virtinst", ver:"0.500.1-2ubuntu6.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
