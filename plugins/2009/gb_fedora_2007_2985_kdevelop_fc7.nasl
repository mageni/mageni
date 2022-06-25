###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for kdevelop FEDORA-2007-2985
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
tag_insight = "The KDevelop Integrated Development Environment provides many features
  that developers need as well as providing a unified interface to programs
  like gdb, the C/C++ compiler, and make. KDevelop manages or provides:

  All development tools needed for C++ programming like Compiler,
  Linker, automake and autoconf; KAppWizard, which generates complete,
  ready-to-go sample applications; Classgenerator, for creating new
  classes and integrating them into the current project; File management
  for sources, headers, documentation etc. to be included in the
  project; The creation of User-Handbooks written with SGML and the
  automatic generation of HTML-output with the KDE look and feel;
  Automatic HTML-based API-documentation for your project's classes with
  cross-references to the used libraries; Internationalization support
  for your application, allowing translators to easily add their target
  language to a project;
  
  KDevelop also includes WYSIWYG (What you see is what you get)-creation
  of user interfaces with a built-in dialog editor; Debugging your
  application by integrating KDbg; Editing of project-specific pixmaps
  with KIconEdit; The inclusion of any other program you need for
  development by adding it to the &quot;Tools&quot;-menu according to your
  individual needs.";

tag_affected = "kdevelop on Fedora 7";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-November/msg00321.html");
  script_oid("1.3.6.1.4.1.25623.1.0.307801");
  script_version("$Revision: 6623 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 08:10:20 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:01:32 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2007-2985");
  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_name( "Fedora Update for kdevelop FEDORA-2007-2985");

  script_tag(name:"summary", value:"Check for the Version of kdevelop");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC7")
{

  if ((res = isrpmvuln(pkg:"kdevelop", rpm:"kdevelop~3.5.0~4.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdevelop-debuginfo", rpm:"kdevelop-debuginfo~3.5.0~4.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdevelop-devel", rpm:"kdevelop-devel~3.5.0~4.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdevelop", rpm:"kdevelop~3.5.0~4.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdevelop", rpm:"kdevelop~3.5.0~4.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdevelop-devel", rpm:"kdevelop-devel~3.5.0~4.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdevelop-debuginfo", rpm:"kdevelop-debuginfo~3.5.0~4.fc7", rls:"FC7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
