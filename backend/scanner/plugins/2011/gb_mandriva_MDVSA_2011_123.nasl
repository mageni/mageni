###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for squirrelmail MDVSA-2011:123 (squirrelmail)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-08/msg00005.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831438");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");
  script_name("Mandriva Update for squirrelmail MDVSA-2011:123 (squirrelmail)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrelmail'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"squirrelmail on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in
  squirrelmail:

  functions/page_header.php in SquirrelMail 1.4.21 and earlier does not
  prevent page rendering inside a frame in a third-party HTML document,
  which makes it easier for remote attackers to conduct clickjacking
  attacks via a crafted web site (CVE-2010-4554).

  Multiple cross-site scripting (XSS) vulnerabilities in SquirrelMail
  1.4.21 and earlier allow remote attackers to inject arbitrary
  web script or HTML via vectors involving (1) drop-down selection
  lists, (2) the > (greater than) character in the SquirrelSpell
  spellchecking plugin, and (3) errors associated with the Index Order
  (aka options_order) page (CVE-2010-4555).

  Cross-site scripting (XSS) vulnerability in functions/mime.php in
  SquirrelMail before 1.4.22 allows remote attackers to inject arbitrary
  web script or HTML via a crafted STYLE element in an e-mail message
  (CVE-2011-2023).

  CRLF injection vulnerability in SquirrelMail 1.4.21 and earlier
  allows remote attackers to modify or add preference values via a \n
  (newline) character, a different vulnerability than CVE-2010-4555
  (CVE-2011-2752).

  Multiple cross-site request forgery (CSRF) vulnerabilities in
  SquirrelMail 1.4.21 and earlier allow remote attackers to hijack the
  authentication of unspecified victims via vectors involving (1) the
  empty trash implementation and (2) the Index Order (aka options_order)
  page, a different issue than CVE-2010-4555 (CVE-2011-2753).

  The updated packages have been upgraded to the 1.4.22 version which
  is not vulnerable to these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ar", rpm:"squirrelmail-ar~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-bg", rpm:"squirrelmail-bg~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-bn-bangladesh", rpm:"squirrelmail-bn-bangladesh~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-bn-india", rpm:"squirrelmail-bn-india~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ca", rpm:"squirrelmail-ca~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-cs", rpm:"squirrelmail-cs~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-cy", rpm:"squirrelmail-cy~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-cyrus", rpm:"squirrelmail-cyrus~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-da", rpm:"squirrelmail-da~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-de", rpm:"squirrelmail-de~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-el", rpm:"squirrelmail-el~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-es", rpm:"squirrelmail-es~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-et", rpm:"squirrelmail-et~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-eu", rpm:"squirrelmail-eu~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fa", rpm:"squirrelmail-fa~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fi", rpm:"squirrelmail-fi~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fo", rpm:"squirrelmail-fo~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fr", rpm:"squirrelmail-fr~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-fy", rpm:"squirrelmail-fy~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-he", rpm:"squirrelmail-he~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-hr", rpm:"squirrelmail-hr~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-hu", rpm:"squirrelmail-hu~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-id", rpm:"squirrelmail-id~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-is", rpm:"squirrelmail-is~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-it", rpm:"squirrelmail-it~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ja", rpm:"squirrelmail-ja~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ka", rpm:"squirrelmail-ka~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-km", rpm:"squirrelmail-km~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ko", rpm:"squirrelmail-ko~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-lt", rpm:"squirrelmail-lt~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-lv", rpm:"squirrelmail-lv~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-mk", rpm:"squirrelmail-mk~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ms", rpm:"squirrelmail-ms~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-nb", rpm:"squirrelmail-nb~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-nl", rpm:"squirrelmail-nl~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-nn", rpm:"squirrelmail-nn~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-pl", rpm:"squirrelmail-pl~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-poutils", rpm:"squirrelmail-poutils~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-pt", rpm:"squirrelmail-pt~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ro", rpm:"squirrelmail-ro~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ru", rpm:"squirrelmail-ru~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-sk", rpm:"squirrelmail-sk~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-sl", rpm:"squirrelmail-sl~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-sr", rpm:"squirrelmail-sr~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-sv", rpm:"squirrelmail-sv~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ta", rpm:"squirrelmail-ta~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-th", rpm:"squirrelmail-th~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-tr", rpm:"squirrelmail-tr~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-ug", rpm:"squirrelmail-ug~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-uk", rpm:"squirrelmail-uk~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-vi", rpm:"squirrelmail-vi~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-zh_CN", rpm:"squirrelmail-zh_CN~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squirrelmail-zh_TW", rpm:"squirrelmail-zh_TW~1.4.22~0.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
