###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mono FEDORA-2007-067
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
tag_affected = "mono on Fedora Core 6";
tag_insight = "The Mono runtime implements a JIT engine for the ECMA CLI
  virtual machine (as well as a byte code interpreter, the
  class loader, the garbage collector, threading system and
  metadata access libraries.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-January/msg00068.html");
  script_oid("1.3.6.1.4.1.25623.1.0.310990");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name: "FEDORA", value: "2007-067");
  script_cve_id("CVE-2006-6104");
  script_name( "Fedora Update for mono FEDORA-2007-067");

  script_tag(name:"summary", value:"Check for the Version of mono");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
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

if(release == "FC6")
{

  if ((res = isrpmvuln(pkg:"mono", rpm:"mono~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-jscript", rpm:"x86_64/mono-jscript~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-data-sybase", rpm:"x86_64/mono-data-sybase~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-data-sqlite", rpm:"x86_64/mono-data-sqlite~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-core", rpm:"x86_64/mono-core~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-web", rpm:"x86_64/mono-web~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-extras", rpm:"x86_64/mono-extras~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/bytefx-data-mysql", rpm:"x86_64/bytefx-data-mysql~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-nunit-devel", rpm:"x86_64/mono-nunit-devel~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-locale-extras", rpm:"x86_64/mono-locale-extras~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ibm-data-db2", rpm:"x86_64/ibm-data-db2~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-winforms", rpm:"x86_64/mono-winforms~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-data-oracle", rpm:"x86_64/mono-data-oracle~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-data-firebird", rpm:"x86_64/mono-data-firebird~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-nunit", rpm:"x86_64/mono-nunit~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-data-postgresql", rpm:"x86_64/mono-data-postgresql~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-data", rpm:"x86_64/mono-data~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/mono-debuginfo", rpm:"x86_64/debug/mono-debuginfo~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/mono-devel", rpm:"x86_64/mono-devel~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-data-sqlite", rpm:"i386/mono-data-sqlite~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-nunit", rpm:"i386/mono-nunit~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-data", rpm:"i386/mono-data~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-jscript", rpm:"i386/mono-jscript~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-data-oracle", rpm:"i386/mono-data-oracle~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-core", rpm:"i386/mono-core~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/mono-debuginfo", rpm:"i386/debug/mono-debuginfo~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-winforms", rpm:"i386/mono-winforms~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-nunit-devel", rpm:"i386/mono-nunit-devel~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-devel", rpm:"i386/mono-devel~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-data-postgresql", rpm:"i386/mono-data-postgresql~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/bytefx-data-mysql", rpm:"i386/bytefx-data-mysql~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-data-sybase", rpm:"i386/mono-data-sybase~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-web", rpm:"i386/mono-web~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-data-firebird", rpm:"i386/mono-data-firebird~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ibm-data-db2", rpm:"i386/ibm-data-db2~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-extras", rpm:"i386/mono-extras~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/mono-locale-extras", rpm:"i386/mono-locale-extras~1.1.17.1~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}