###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for xen FEDORA-2007-343
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
tag_insight = "This package contains the Xen hypervisor and Xen tools, needed to
  run virtual machines on x86 systems, together with the kernel-xen*
  packages.  Information on how to use Xen can be found at the Xen
  project pages.

  Virtualisation can be used to run multiple versions or multiple
  Linux distributions on one system, or to test untrusted applications
  in a sandboxed environment.";

tag_affected = "xen on Fedora Core 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-March/msg00056.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311676");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:23:18 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_xref(name: "FEDORA", value: "2007-343");
  script_cve_id("CVE-2007-0998");
  script_name( "Fedora Update for xen FEDORA-2007-343");

  script_tag(name:"summary", value:"Check for the Version of xen");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
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

if(release == "FC6")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/xen-debuginfo", rpm:"x86_64/debug/xen-debuginfo~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xen", rpm:"x86_64/xen~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xen-libs", rpm:"x86_64/xen-libs~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/xen-devel", rpm:"x86_64/xen-devel~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/xen-debuginfo", rpm:"i386/debug/xen-debuginfo~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xen-libs", rpm:"i386/xen-libs~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xen-devel", rpm:"i386/xen-devel~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/xen", rpm:"i386/xen~3.0.3~8.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
