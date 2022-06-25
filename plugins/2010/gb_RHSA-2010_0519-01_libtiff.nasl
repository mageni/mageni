###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libtiff RHSA-2010:0519-01
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
tag_insight = "The libtiff packages contain a library of functions for manipulating Tagged
  Image File Format (TIFF) files.

  Multiple integer overflow flaws, leading to a buffer overflow, were
  discovered in libtiff. An attacker could use these flaws to create a
  specially-crafted TIFF file that, when opened, would cause an application
  linked against libtiff to crash or, possibly, execute arbitrary code.
  (CVE-2010-1411)
  
  Multiple input validation flaws were discovered in libtiff. An attacker
  could use these flaws to create a specially-crafted TIFF file that, when
  opened, would cause an application linked against libtiff to crash.
  (CVE-2010-2481, CVE-2010-2483, CVE-2010-2595, CVE-2010-2597)
  
  Red Hat would like to thank Apple Product Security for responsibly
  reporting the CVE-2010-1411 flaw, who credit Kevin Finisterre of
  digitalmunition.com for the discovery of the issue.
  
  All libtiff users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. All running
  applications linked against libtiff must be restarted for this update to
  take effect.";

tag_affected = "libtiff on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-July/msg00003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313805");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-12 11:56:20 +0200 (Mon, 12 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "RHSA", value: "2010:0519-01");
  script_cve_id("CVE-2010-1411", "CVE-2010-2481", "CVE-2010-2483", "CVE-2010-2595", "CVE-2010-2597");
  script_name("RedHat Update for libtiff RHSA-2010:0519-01");

  script_tag(name: "summary" , value: "Check for the Version of libtiff");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.8.2~7.el5_5.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-debuginfo", rpm:"libtiff-debuginfo~3.8.2~7.el5_5.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~3.8.2~7.el5_5.5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.6.1~12.el4_8.5", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-debuginfo", rpm:"libtiff-debuginfo~3.6.1~12.el4_8.5", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~3.6.1~12.el4_8.5", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
