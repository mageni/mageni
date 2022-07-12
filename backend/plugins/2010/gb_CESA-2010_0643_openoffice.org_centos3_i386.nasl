###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openoffice.org CESA-2010:0643 centos3 i386
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
tag_insight = "OpenOffice.org is an office productivity suite that includes desktop
  applications, such as a word processor, spreadsheet application,
  presentation manager, formula editor, and a drawing program.

  An integer truncation error, leading to a heap-based buffer overflow, was
  found in the way the OpenOffice.org Impress presentation application
  sanitized a file's dictionary property items. An attacker could use this
  flaw to create a specially-crafted Microsoft Office PowerPoint file that,
  when opened, would cause OpenOffice.org Impress to crash or, possibly,
  execute arbitrary code with the privileges of the user running
  OpenOffice.org Impress. (CVE-2010-2935)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way OpenOffice.org Impress processed polygons in input
  documents. An attacker could use this flaw to create a specially-crafted
  Microsoft Office PowerPoint file that, when opened, would cause
  OpenOffice.org Impress to crash or, possibly, execute arbitrary code with
  the privileges of the user running OpenOffice.org Impress. (CVE-2010-2936)

  All users of OpenOffice.org are advised to upgrade to these updated
  packages, which contain backported patches to correct these issues. For Red
  Hat Enterprise Linux 3, this erratum provides updated openoffice.org
  packages. For Red Hat Enterprise Linux 4, this erratum provides updated
  openoffice.org and openoffice.org2 packages. All running instances of
  OpenOffice.org applications must be restarted for this update to take
  effect.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "openoffice.org on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-August/016936.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314759");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-30 16:59:25 +0200 (Mon, 30 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-2935", "CVE-2010-2936");
  script_name("CentOS Update for openoffice.org CESA-2010:0643 centos3 i386");

  script_tag(name: "summary" , value: "Check for the Version of openoffice.org");
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

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~1.1.2~48.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-i18n", rpm:"openoffice.org-i18n~1.1.2~48.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-libs", rpm:"openoffice.org-libs~1.1.2~48.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
