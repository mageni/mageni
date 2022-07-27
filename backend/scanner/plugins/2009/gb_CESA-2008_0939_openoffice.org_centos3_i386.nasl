###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for openoffice.org CESA-2008:0939 centos3 i386
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
tag_insight = "OpenOffice.org is an office productivity suite that includes desktop
  applications such as a word processor, spreadsheet, presentation manager,
  formula editor, and drawing program.

  SureRun Security Team discovered an integer overflow flaw leading to a heap
  buffer overflow in the Windows Metafile (WMF) image format parser. An
  attacker could create a carefully crafted document containing a malicious
  WMF file that could cause OpenOffice.org to crash, or, possibly, execute
  arbitrary code if opened by a victim. (CVE-2008-2237)
  
  Multiple integer overflow flaws were found in the Enhanced Windows Metafile
  (EMF) parser. An attacker could create a carefully crafted document
  containing a malicious EMF file that could cause OpenOffice.org to crash,
  or, possibly, execute arbitrary code if opened by a victim. (CVE-2008-2238)
  
  All users of OpenOffice.org are advised to upgrade to these updated
  packages, which contain backported patches that correct these issues.";

tag_affected = "openoffice.org on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-November/015371.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308151");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2237", "CVE-2008-2238");
  script_name( "CentOS Update for openoffice.org CESA-2008:0939 centos3 i386");

  script_tag(name:"summary", value:"Check for the Version of openoffice.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~1.1.2~43.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-i18n", rpm:"openoffice.org-i18n~1.1.2~43.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-libs", rpm:"openoffice.org-libs~1.1.2~43.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
