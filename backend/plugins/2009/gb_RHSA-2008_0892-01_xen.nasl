###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xen RHSA-2008:0892-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The xen packages contain tools for managing the virtual machine monitor in
  Red Hat Virtualization.

  It was discovered that the hypervisor's para-virtualized framebuffer (PVFB)
  backend failed to validate the frontend's framebuffer description properly.
  This could allow a privileged user in the unprivileged domain (DomU) to
  cause a denial of service, or, possibly, elevate privileges to the
  privileged domain (Dom0). (CVE-2008-1952)
  
  A flaw was found in the QEMU block format auto-detection, when running
  fully-virtualized guests and using Qemu images written on removable media
  (USB storage, 3.5&quot; disks). Privileged users of such fully-virtualized
  guests (DomU), with a raw-formatted disk image, were able to write a header
  to that disk image describing another format. This could allow such guests
  to read arbitrary files in their hypervisor's host (Dom0). (CVE-2008-1945)
  
  Additionally, the following bug is addressed in this update:
  
  * The qcow-create command terminated when invoked due to glibc bounds
  checking on the realpath() function.
  
  Users of xen are advised to upgrade to these updated packages, which
  resolve these security issues and fix this bug.";

tag_affected = "xen on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-October/msg00001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311905");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_xref(name: "RHSA", value: "2008:0892-01");
  script_cve_id("CVE-2008-1945", "CVE-2008-1952");
  script_name( "RedHat Update for xen RHSA-2008:0892-01");

  script_tag(name:"summary", value:"Check for the Version of xen");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"xen-debuginfo", rpm:"xen-debuginfo~3.0.3~64.el5_2.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~64.el5_2.3", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
