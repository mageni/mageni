###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for iptables MDVA-2010:104 (iptables)
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
tag_affected = "iptables on Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64";
tag_insight = "This update adds missing header files which are necessary to compile
  third-party applications based on iptables.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-03/msg00031.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313212");
  script_version("$Revision: 8485 $");
  script_cve_id("CVE-2010-0745");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-22 11:34:53 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "MDVA", value: "2010:104");
  script_name("Mandriva Update for iptables MDVA-2010:104 (iptables)");

  script_tag(name: "summary" , value: "Check for the Version of iptables");
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

  if ((res = isrpmvuln(pkg:"iptables", rpm:"iptables~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libip4tc0", rpm:"libip4tc0~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libip4tc-devel", rpm:"libip4tc-devel~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libip6tc0", rpm:"libip6tc0~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libip6tc-devel", rpm:"libip6tc-devel~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiptables2", rpm:"libiptables2~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiptables-devel", rpm:"libiptables-devel~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiptc0", rpm:"libiptc0~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiptc-devel", rpm:"libiptc-devel~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ip4tc0", rpm:"lib64ip4tc0~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ip4tc-devel", rpm:"lib64ip4tc-devel~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ip6tc0", rpm:"lib64ip6tc0~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64ip6tc-devel", rpm:"lib64ip6tc-devel~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64iptables2", rpm:"lib64iptables2~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64iptables-devel", rpm:"lib64iptables-devel~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64iptc0", rpm:"lib64iptc0~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64iptc-devel", rpm:"lib64iptc-devel~1.4.5~3.1mnb2", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"iptables", rpm:"iptables~1.4.3.1~4.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiptables1", rpm:"libiptables1~1.4.3.1~4.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libiptables-devel", rpm:"libiptables-devel~1.4.3.1~4.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64iptables1", rpm:"lib64iptables1~1.4.3.1~4.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64iptables-devel", rpm:"lib64iptables-devel~1.4.3.1~4.1mnb2", rls:"MNDK_2009.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
