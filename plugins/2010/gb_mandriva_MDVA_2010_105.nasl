###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for lvm2 MDVA-2010:105 (lvm2)
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
tag_affected = "lvm2 on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";
tag_insight = "Updated packages for lvm2 and device mapper correct malfunctioning
  of dmeventd and errors while creating snapshots and mirrored targets.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-03/msg00030.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314783");
  script_version("$Revision: 8528 $");
  script_cve_id("CVE-2009-0200", "CVE-2009-0201", "CVE-2009-2139", "CVE-2009-2140",
                "CVE-2009-3736");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-22 11:34:53 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVA", value: "2010:105");
  script_name("Mandriva Update for lvm2 MDVA-2010:105 (lvm2)");

  script_tag(name: "summary" , value: "Check for the Version of lvm2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"clvmd", rpm:"clvmd~2.02.53~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dmsetup", rpm:"dmsetup~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdevmapper1.02", rpm:"libdevmapper1.02~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdevmapper-devel", rpm:"libdevmapper-devel~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdevmapper-event1.02", rpm:"libdevmapper-event1.02~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdevmapper-event-devel", rpm:"libdevmapper-event-devel~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblvm2cmd2.02", rpm:"liblvm2cmd2.02~2.02.53~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"liblvm2cmd-devel", rpm:"liblvm2cmd-devel~2.02.53~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lvm2", rpm:"lvm2~2.02.53~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64devmapper1.02", rpm:"lib64devmapper1.02~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64devmapper-devel", rpm:"lib64devmapper-devel~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64devmapper-event1.02", rpm:"lib64devmapper-event1.02~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64devmapper-event-devel", rpm:"lib64devmapper-event-devel~1.02.38~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64lvm2cmd2.02", rpm:"lib64lvm2cmd2.02~2.02.53~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64lvm2cmd-devel", rpm:"lib64lvm2cmd-devel~2.02.53~9.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
