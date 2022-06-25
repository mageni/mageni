###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for blogtk MDVA-2010:070-1 (blogtk)
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
tag_insight = "The blogtk package in 2010.0 was crashing on start. This update fixes
  the problem by updating blogtk to the latest version.

  Additionally the python-gdata packages are being provided as well
  due to requirements.
  
  Update:
  
  The MDVA-2010:070 advisory was missing some new dependencies (packages)
  that prevented blogtk to install using MandrivaUpdate. This advisory
  provides the missing packages.";

tag_affected = "blogtk on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-02/msg00045.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313467");
  script_version("$Revision: 8274 $");
  script_cve_id("CVE-2010-0164", "CVE-2010-0165", "CVE-2010-0167", "CVE-2010-0168",
                "CVE-2010-0170", "CVE-2010-0172", "CVE-2010-0173", "CVE-2010-0174",
                "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178",
                "CVE-2010-0179", "CVE-2010-0181", "CVE-2010-0182", "CVE-2010-1122");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:38:33 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVA", value: "2010:070-1");
  script_name("Mandriva Update for blogtk MDVA-2010:070-1 (blogtk)");

  script_tag(name: "summary" , value: "Check for the Version of blogtk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"gtksourceview", rpm:"gtksourceview~2.8.1~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgtksourceview", rpm:"libgtksourceview~2.0_0~2.8.1~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgtksourceview", rpm:"libgtksourceview~2.0~devel~2.8.1~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-gtksourceview", rpm:"python-gtksourceview~2.8.0~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-gtksourceview-devel", rpm:"python-gtksourceview-devel~2.8.0~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-webkitgtk", rpm:"python-webkitgtk~1.1.5~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gtksourceview", rpm:"lib64gtksourceview~2.0_0~2.8.1~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gtksourceview", rpm:"lib64gtksourceview~2.0~devel~2.8.1~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
