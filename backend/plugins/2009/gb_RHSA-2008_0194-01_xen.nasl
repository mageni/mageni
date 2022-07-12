###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xen RHSA-2008:0194-01
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

  These updated packages fix the following security issues:
  
  Daniel P. Berrange discovered that the hypervisor's para-virtualized
  framebuffer (PVFB) backend failed to validate the format of messages
  serving to update the contents of the framebuffer. This could allow a
  malicious user to cause a denial of service, or compromise the privileged
  domain (Dom0). (CVE-2008-1944)
  
  Markus Armbruster discovered that the hypervisor's para-virtualized
  framebuffer (PVFB) backend failed to validate the frontend's framebuffer
  description. This could allow a malicious user to cause a denial of
  service, or to use a specially crafted frontend to compromise the
  privileged domain (Dom0). (CVE-2008-1943)
  
  Chris Wright discovered a security vulnerability in the QEMU block format
  auto-detection, when running fully-virtualized guests. Such
  fully-virtualized guests, with a raw formatted disk image, were able
  to write a header to that disk image describing another format. This could
  allow such guests to read arbitrary files in their hypervisor's host.
  (CVE-2008-2004)
  
  Ian Jackson discovered a security vulnerability in the QEMU block device
  drivers backend. A guest operating system could issue a block device
  request and read or write arbitrary memory locations, which could lead to
  privilege escalation. (CVE-2008-0928)
  
  Tavis Ormandy found that QEMU did not perform adequate sanity-checking of
  data received via the &quot;net socket listen&quot; option. A malicious local
  administrator of a guest domain could trigger this flaw to potentially
  execute arbitrary code outside of the domain. (CVE-2007-5730)
  
  Steve Kemp discovered that the xenbaked daemon and the XenMon utility
  communicated via an insecure temporary file. A malicious local
  administrator of a guest domain could perform a symbolic link attack,
  causing arbitrary files to be truncated. (CVE-2007-3919)
  
  As well, in the previous xen packages, it was possible for Dom0 to fail to
  flush data from a fully-virtualized guest to disk, even if the guest
  explicitly requested the flush. This could cause data integrity problems on
  the guest. In these updated packages, Dom0 always respects the request to
  flush to disk.
  
  Users of xen are advised to upgrade to these updated packages, which
  resolve these issues.";

tag_affected = "xen on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-May/msg00006.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310815");
  script_version("$Revision: 6683 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:41:57 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2008:0194-01");
  script_cve_id("CVE-2007-3919", "CVE-2007-5730", "CVE-2008-0928", "CVE-2008-1943", "CVE-2008-1944", "CVE-2008-2004");
  script_name( "RedHat Update for xen RHSA-2008:0194-01");

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

  if ((res = isrpmvuln(pkg:"xen-debuginfo", rpm:"xen-debuginfo~3.0.3~41.el5_1.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~41.el5_1.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
