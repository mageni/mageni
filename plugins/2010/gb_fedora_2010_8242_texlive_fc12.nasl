###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for texlive FEDORA-2010-8242
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
tag_insight = "TeXLive is an implementation of TeX for Linux or UNIX systems. TeX takes
  a text file and a set of formatting commands as input and creates a
  printable file as output. Usually, TeX is used in conjunction with
  a higher level formatting package like LaTeX or PlainTeX, since TeX by
  itself is not very user-friendly.

  Install texlive if you want to use the TeX text formatting system. Consider
  to install texlive-latex (a higher level formatting package which provides
  an easier-to-use interface for TeX).
  
  The TeX documentation is located in the texlive-doc package.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "texlive on Fedora 12";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-May/041567.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314264");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-28 10:00:59 +0200 (Fri, 28 May 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2010-8242");
  script_cve_id("CVE-2010-0739", "CVE-2010-1440", "CVE-2010-0829");
  script_name("Fedora Update for texlive FEDORA-2010-8242");

  script_tag(name: "summary" , value: "Check for the Version of texlive");
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"texlive", rpm:"texlive~2007~48.fc12", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
