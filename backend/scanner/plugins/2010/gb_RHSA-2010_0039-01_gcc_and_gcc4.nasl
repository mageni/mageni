###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for gcc and gcc4 RHSA-2010:0039-01
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
tag_insight = "The gcc and gcc4 packages include, among others, C, C++, and Java GNU
  compilers and related support libraries. libgcj contains a copy of GNU
  Libtool's libltdl library.

  A flaw was found in the way GNU Libtool's libltdl library looked for
  libraries to load. It was possible for libltdl to load a malicious library
  from the current working directory. In certain configurations, if a local
  attacker is able to trick a local user into running a Java application
  (which uses a function to load native libraries, such as
  System.loadLibrary) from within an attacker-controlled directory containing
  a malicious library or module, the attacker could possibly execute
  arbitrary code with the privileges of the user running the Java
  application. (CVE-2009-3736)
  
  All gcc and gcc4 users should upgrade to these updated packages, which
  contain a backported patch to correct this issue. All running Java
  applications using libgcj must be restarted for this update to take effect.";

tag_affected = "gcc and gcc4 on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 3,
  Red Hat Enterprise Linux WS version 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-January/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313797");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-01-19 08:58:46 +0100 (Tue, 19 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0039-01");
  script_cve_id("CVE-2009-3736");
  script_name("RedHat Update for gcc and gcc4 RHSA-2010:0039-01");

  script_tag(name: "summary" , value: "Check for the Version of gcc and gcc4");
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

  if ((res = isrpmvuln(pkg:"cpp", rpm:"cpp~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc", rpm:"gcc~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-c++", rpm:"gcc-c++~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-debuginfo", rpm:"gcc-debuginfo~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-gfortran", rpm:"gcc-gfortran~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-gnat", rpm:"gcc-gnat~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-java", rpm:"gcc-java~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-objc++", rpm:"gcc-objc++~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-objc", rpm:"gcc-objc~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcc", rpm:"libgcc~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj", rpm:"libgcj~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj-devel", rpm:"libgcj-devel~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj-src", rpm:"libgcj-src~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgfortran", rpm:"libgfortran~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnat", rpm:"libgnat~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmudflap", rpm:"libmudflap~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmudflap-devel", rpm:"libmudflap-devel~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libobjc", rpm:"libobjc~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++", rpm:"libstdc++~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++-devel", rpm:"libstdc++-devel~4.1.2~46.el5_4.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"cpp", rpm:"cpp~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc", rpm:"gcc~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-c++", rpm:"gcc-c++~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-debuginfo", rpm:"gcc-debuginfo~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-g77", rpm:"gcc-g77~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-gnat", rpm:"gcc-gnat~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-java", rpm:"gcc-java~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-objc", rpm:"gcc-objc~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc4", rpm:"gcc4~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc4-c++", rpm:"gcc4-c++~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc4-debuginfo", rpm:"gcc4-debuginfo~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc4-gfortran", rpm:"gcc4-gfortran~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc4-java", rpm:"gcc4-java~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libf2c", rpm:"libf2c~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcc", rpm:"libgcc~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj", rpm:"libgcj~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj-devel", rpm:"libgcj-devel~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj4", rpm:"libgcj4~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj4-devel", rpm:"libgcj4-devel~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj4-src", rpm:"libgcj4-src~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgfortran", rpm:"libgfortran~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnat", rpm:"libgnat~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgomp", rpm:"libgomp~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmudflap", rpm:"libmudflap~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libmudflap-devel", rpm:"libmudflap-devel~4.1.2~44.EL4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libobjc", rpm:"libobjc~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++", rpm:"libstdc++~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++-devel", rpm:"libstdc++-devel~3.4.6~11.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"cpp", rpm:"cpp~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc", rpm:"gcc~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-c++", rpm:"gcc-c++~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-debuginfo", rpm:"gcc-debuginfo~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-g77", rpm:"gcc-g77~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-gnat", rpm:"gcc-gnat~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-java", rpm:"gcc-java~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gcc-objc", rpm:"gcc-objc~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libf2c", rpm:"libf2c~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcc", rpm:"libgcc~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj", rpm:"libgcj~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgcj-devel", rpm:"libgcj-devel~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnat", rpm:"libgnat~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libobjc", rpm:"libobjc~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++", rpm:"libstdc++~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libstdc++-devel", rpm:"libstdc++-devel~3.2.3~60", rls:"RHENT_3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
