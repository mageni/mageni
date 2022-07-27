###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2007:1049 centos3 x86_64
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
tag_insight = "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  A flaw was found in the handling of process death signals. This allowed a
  local user to send arbitrary signals to the suid-process executed by that
  user. A successful exploitation of this flaw depends on the structure of
  the suid-program and its signal handling. (CVE-2007-3848, Important)
  
  A flaw was found in the IPv4 forwarding base. This allowed a local user to
  cause a denial of service. (CVE-2007-2172, Important) 
  
  A flaw was found where a corrupted executable file could cause cross-region
  memory mappings on Itanium systems. This allowed a local user to cause a
  denial of service. (CVE-2006-4538, Moderate) 
  
  A flaw was found in the stack expansion when using the hugetlb kernel on
  PowerPC systems. This allowed a local user to cause a denial of service.
  (CVE-2007-3739, Moderate) 
  
  A flaw was found in the aacraid SCSI driver. This allowed a local user to
  make ioctl calls to the driver that should be restricted to privileged
  users. (CVE-2007-4308, Moderate) 
  
  As well, these updated packages fix the following bug:
  
  * a bug in the TCP header prediction code may have caused &quot;TCP: Treason
  uncloaked!&quot; messages to be logged. In certain situations this may have lead
  to TCP connections hanging or aborting.
  
  Red Hat Enterprise Linux 3 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.";

tag_affected = "kernel on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2007-December/014480.html");
  script_oid("1.3.6.1.4.1.25623.1.0.305594");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:31:09 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2007-2172", "CVE-2007-3848", "CVE-2006-4538", "CVE-2007-3739", "CVE-2007-4308");
  script_name( "CentOS Update for kernel CESA-2007:1049 centos3 x86_64");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.4.21~53.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.4.21~53.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.4.21~53.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-unsupported", rpm:"kernel-smp-unsupported~2.4.21~53.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.4.21~53.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-unsupported", rpm:"kernel-unsupported~2.4.21~53.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
