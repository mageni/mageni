###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for wireshark MDVSA-2010:200 (wireshark)
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
tag_insight = "It was discovered that the ASN.1 BER dissector in wireshark was
  susceptible to a stack overflow (CVE-2010-3445).

  For 2010.0 and 2010.1 wireshark was upgraded to v1.2.12 which is not
  vulnerable to this issue and was patched for CS4 and MES5 to resolve
  the vulnerability.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "wireshark on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-10/msg00021.php");
  script_oid("1.3.6.1.4.1.25623.1.0.313712");
  script_version("$Revision: 8485 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-22 08:57:57 +0100 (Mon, 22 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-19 15:54:15 +0200 (Tue, 19 Oct 2010)");
  script_xref(name: "MDVSA", value: "2010:200");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-3445");
  script_name("Mandriva Update for wireshark MDVSA-2010:200 (wireshark)");

  script_tag(name: "summary" , value: "Check for the Version of wireshark");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark0", rpm:"libwireshark0~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark0", rpm:"lib64wireshark0~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.0.15~0.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark0", rpm:"libwireshark0~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark0", rpm:"lib64wireshark0~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.2.12~0.1mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"dumpcap", rpm:"dumpcap~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark0", rpm:"libwireshark0~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwireshark-devel", rpm:"libwireshark-devel~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rawshark", rpm:"rawshark~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tshark", rpm:"tshark~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-tools", rpm:"wireshark-tools~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark0", rpm:"lib64wireshark0~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64wireshark-devel", rpm:"lib64wireshark-devel~1.2.12~0.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
