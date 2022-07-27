###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for qt FEDORA-2010-8379
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
tag_insight = "Qt is a software toolkit for developing applications.

  This package contains base tools, like string, xml, and network
  handling.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "qt on Fedora 11";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-May/041432.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313997");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-17 16:00:10 +0200 (Mon, 17 May 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-8379");
  script_cve_id("CVE-2010-0047", "CVE-2010-0648", "CVE-2010-0656", "CVE-2010-0046", "CVE-2010-0049", "CVE-2010-0050", "CVE-2010-0051", "CVE-2010-0052", "CVE-2010-0054", "CVE-2009-2700", "CVE-2009-1725", "CVE-2010-0048", "CVE-2010-0053");
  script_name("Fedora Update for qt FEDORA-2010-8379");

  script_tag(name: "summary" , value: "Check for the Version of qt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC11")
{

  if ((res = isrpmvuln(pkg:"qt", rpm:"qt~4.6.2~17.fc11", rls:"FC11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
