###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mozilla-thunderbird MDVSA-2008:155-1 (mozilla-thunderbird)
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
tag_insight = "A number of security vulnerabilities have been discovered and
  corrected in the latest Mozilla Thunderbird program, version 2.0.0.16
  (CVE-2008-1233, CVE-2008-1234, CVE-2008-1235, CVE-2008-1236,
  CVE-2008-1237, CVE-2008-2785, CVE-2008-2798, CVE-2008-2799,
  CVE-2008-2802, CVE-2008-2803, CVE-2008-2807, CVE-2008-2809,
  CVE-2008-2811).

  This update provides the latest Thunderbird to correct these issues.
  It also provides Thunderbird 2.x for Corporate 3.0 systems.
  
  Update:
  
  The previous update provided the incorrect version of the enigmail
  locale files.  This version correctly builds them for Thunderbird
  2.0.0.16.";

tag_affected = "mozilla-thunderbird on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-07/msg00043.php");
  script_oid("1.3.6.1.4.1.25623.1.0.308556");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:155-1");
  script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2807", "CVE-2008-2809", "CVE-2008-2811");
  script_name( "Mandriva Update for mozilla-thunderbird MDVSA-2008:155-1 (mozilla-thunderbird)");

  script_tag(name:"summary", value:"Check for the Version of mozilla-thunderbird");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es_AR", rpm:"mozilla-thunderbird-enigmail-es_AR~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ro", rpm:"mozilla-thunderbird-enigmail-ro~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sk", rpm:"mozilla-thunderbird-enigmail-sk~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-l10n", rpm:"mozilla-thunderbird-enigmail-l10n~2.0.0.16~1mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ar", rpm:"mozilla-thunderbird-enigmail-ar~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ca", rpm:"mozilla-thunderbird-enigmail-ca~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-cs", rpm:"mozilla-thunderbird-enigmail-cs~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-de", rpm:"mozilla-thunderbird-enigmail-de~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-el", rpm:"mozilla-thunderbird-enigmail-el~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es", rpm:"mozilla-thunderbird-enigmail-es~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-es_AR", rpm:"mozilla-thunderbird-enigmail-es_AR~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fi", rpm:"mozilla-thunderbird-enigmail-fi~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-fr", rpm:"mozilla-thunderbird-enigmail-fr~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-hu", rpm:"mozilla-thunderbird-enigmail-hu~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-it", rpm:"mozilla-thunderbird-enigmail-it~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ja", rpm:"mozilla-thunderbird-enigmail-ja~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ko", rpm:"mozilla-thunderbird-enigmail-ko~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nb", rpm:"mozilla-thunderbird-enigmail-nb~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-nl", rpm:"mozilla-thunderbird-enigmail-nl~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pl", rpm:"mozilla-thunderbird-enigmail-pl~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt", rpm:"mozilla-thunderbird-enigmail-pt~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-pt_BR", rpm:"mozilla-thunderbird-enigmail-pt_BR~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ro", rpm:"mozilla-thunderbird-enigmail-ro~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-ru", rpm:"mozilla-thunderbird-enigmail-ru~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sk", rpm:"mozilla-thunderbird-enigmail-sk~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sl", rpm:"mozilla-thunderbird-enigmail-sl~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-sv", rpm:"mozilla-thunderbird-enigmail-sv~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-tr", rpm:"mozilla-thunderbird-enigmail-tr~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_CN", rpm:"mozilla-thunderbird-enigmail-zh_CN~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-zh_TW", rpm:"mozilla-thunderbird-enigmail-zh_TW~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-enigmail-l10n", rpm:"mozilla-thunderbird-enigmail-l10n~2.0.0.16~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
