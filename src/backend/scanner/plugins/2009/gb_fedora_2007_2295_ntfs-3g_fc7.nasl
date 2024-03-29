###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ntfs-3g FEDORA-2007-2295
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
tag_insight = "The ntfs-3g driver is an open source, GPL licensed, third generation
  Linux NTFS driver. It provides full read-write access to NTFS, excluding
  access to encrypted files, writing compressed files, changing file
  ownership, access right.

  Technically it�s based on and a major improvement to the third
  generation Linux NTFS driver, ntfsmount. The improvements include
  functionality, quality and performance enhancements.
  
  ntfs-3g features are being merged to ntfsmount. In the meanwhile,
  ntfs-3g is currently the only free, as in either speech or beer, NTFS
  driver for Linux that supports unlimited file creation and deletion.";

tag_affected = "ntfs-3g on Fedora 7";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-September/msg00368.html");
  script_oid("1.3.6.1.4.1.25623.1.0.306189");
  script_cve_id("CVE-2007-5159");
 script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2007-2295");
  script_name( "Fedora Update for ntfs-3g FEDORA-2007-2295");

  script_tag(name:"summary", value:"Check for the Version of ntfs-3g");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~1.913~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~1.913~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g-devel", rpm:"ntfs-3g-devel~1.913~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g-debuginfo", rpm:"ntfs-3g-debuginfo~1.913~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g-devel", rpm:"ntfs-3g-devel~1.913~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g-debuginfo", rpm:"ntfs-3g-debuginfo~1.913~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~1.913~2.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
