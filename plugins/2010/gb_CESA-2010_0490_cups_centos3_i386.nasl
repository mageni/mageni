###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for cups CESA-2010:0490 centos3 i386
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
tag_insight = "The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems. The CUPS &quot;texttops&quot; filter converts text files
  to PostScript.

  A missing memory allocation failure check flaw, leading to a NULL pointer
  dereference, was found in the CUPS &quot;texttops&quot; filter. An attacker could
  create a malicious text file that would cause &quot;texttops&quot; to crash or,
  potentially, execute arbitrary code as the &quot;lp&quot; user if the file was
  printed. (CVE-2010-0542)

  A Cross-Site Request Forgery (CSRF) issue was found in the CUPS web
  interface. If a remote attacker could trick a user, who is logged into the
  CUPS web interface as an administrator, into visiting a specially-crafted
  website, the attacker could reconfigure and disable CUPS, and gain access
  to print jobs and system files. (CVE-2010-0540)

  Note: As a result of the fix for CVE-2010-0540, cookies must now be enabled
  in your web browser to use the CUPS web interface.

  An uninitialized memory read issue was found in the CUPS web interface. If
  an attacker had access to the CUPS web interface, they could use a
  specially-crafted URL to leverage this flaw to read a limited amount of
  memory from the cupsd process, possibly obtaining sensitive information.
  (CVE-2010-1748)

  Red Hat would like to thank the Apple Product Security team for responsibly
  reporting these issues. Upstream acknowledges regenrecht as the original
  reporter of CVE-2010-0542; Adrian 'pagvac' Pastor of GNUCITIZEN and Tim
  Starling as the original reporters of CVE-2010-0540; and Luca Carettoni as
  the original reporter of CVE-2010-1748.

  Users of cups are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing this
  update, the cupsd daemon will be restarted automatically.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "cups on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-August/016914.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314026");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-20 14:57:11 +0200 (Fri, 20 Aug 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0540", "CVE-2010-0542", "CVE-2010-1748");
  script_name("CentOS Update for cups CESA-2010:0490 centos3 i386");

  script_tag(name: "summary" , value: "Check for the Version of cups");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.17~13.3.65", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.1.17~13.3.65", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.1.17~13.3.65", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
