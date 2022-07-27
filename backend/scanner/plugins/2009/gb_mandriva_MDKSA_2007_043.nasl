###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for clamav MDKSA-2007:043 (clamav)
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
tag_insight = "Clam AntiVirus ClamAV before 0.90 does not close open file descriptors
  under certain conditions, which allows remote attackers to cause a
  denial of service (file descriptor consumption and failed scans) via
  CAB archives with a cabinet header record length of zero, which causes
  a function to return without closing a file descriptor. (CVE-2007-0897)

  Directory traversal vulnerability in clamd in Clam AntiVirus ClamAV
  before 0.90 allows remote attackers to overwrite arbitrary files via a
  .. (dot dot) in the id MIME header parameter in a multi-part message.
  (CVE-2007-0898)
  
  The update to 0.90 addresses these issues.";

tag_affected = "clamav on Mandriva Linux 2006.0,
  Mandriva Linux 2006.0/X86_64,
  Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-02/msg00014.php");
  script_oid("1.3.6.1.4.1.25623.1.0.310175");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name: "MDKSA", value: "2007:043");
  script_cve_id("CVE-2007-0897", "CVE-2007-0898");
  script_name( "Mandriva Update for clamav MDKSA-2007:043 (clamav)");

  script_tag(name:"summary", value:"Check for the Version of clamav");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.90~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.90~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.90~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav1", rpm:"libclamav1~0.90~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav1-devel", rpm:"libclamav1-devel~0.90~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav1", rpm:"lib64clamav1~0.90~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav1-devel", rpm:"lib64clamav1-devel~0.90~1.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2006.0")
{

  if ((res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.90~0.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.90~0.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.90~0.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.90~0.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav1", rpm:"libclamav1~0.90~0.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libclamav1-devel", rpm:"libclamav1-devel~0.90~0.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav1", rpm:"lib64clamav1~0.90~0.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64clamav1-devel", rpm:"lib64clamav1-devel~0.90~0.1.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
