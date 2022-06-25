###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for xpdf CESA-2010:0751 centos4 i386
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
tag_insight = "Xpdf is an X Window System based viewer for Portable Document Format (PDF)
  files.

  An uninitialized pointer use flaw was discovered in Xpdf. An attacker could
  create a malicious PDF file that, when opened, would cause Xpdf to crash
  or, potentially, execute arbitrary code. (CVE-2010-3702)
  
  An array index error was found in the way Xpdf parsed PostScript Type 1
  fonts embedded in PDF documents. An attacker could create a malicious PDF
  file that, when opened, would cause Xpdf to crash or, potentially, execute
  arbitrary code. (CVE-2010-3704)
  
  Users are advised to upgrade to this updated package, which contains
  backported patches to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "xpdf on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-October/017047.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313108");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-19 15:54:15 +0200 (Tue, 19 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3702", "CVE-2010-3704");
  script_name("CentOS Update for xpdf CESA-2010:0751 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of xpdf");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~3.00~24.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
