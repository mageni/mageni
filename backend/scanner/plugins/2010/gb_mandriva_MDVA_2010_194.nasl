###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for boost MDVA-2010:194 (boost)
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
tag_affected = "boost on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64";
tag_insight = "Due to a typo in the boost package in Mandriva 2010.1 some files in
  the lib(64)boost-static-devel were symlinked wrongly, this update
  fixes this issue.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-09/msg00023.php");
  script_oid("1.3.6.1.4.1.25623.1.0.314540");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-27 08:14:44 +0200 (Mon, 27 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "MDVA", value: "2010:194");
  script_name("Mandriva Update for boost MDVA-2010:194 (boost)");

  script_tag(name: "summary" , value: "Check for the Version of boost");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"boost-examples", rpm:"boost-examples~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_date_time1.42.0", rpm:"libboost_date_time1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost-devel", rpm:"libboost-devel~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost-devel-doc", rpm:"libboost-devel-doc~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_filesystem1.42.0", rpm:"libboost_filesystem1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_graph1.42.0", rpm:"libboost_graph1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_iostreams1.42.0", rpm:"libboost_iostreams1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_math_c99", rpm:"libboost_math_c99~1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_math_c99f1.42.0", rpm:"libboost_math_c99f1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_math_c99l1.42.0", rpm:"libboost_math_c99l1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_math_tr1", rpm:"libboost_math_tr1~1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_math_tr1f1.42.0", rpm:"libboost_math_tr1f1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_math_tr1l1.42.0", rpm:"libboost_math_tr1l1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_prg_exec_monitor1.42.0", rpm:"libboost_prg_exec_monitor1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_program_options1.42.0", rpm:"libboost_program_options1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_python1.42.0", rpm:"libboost_python1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_regex1.42.0", rpm:"libboost_regex1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_serialization1.42.0", rpm:"libboost_serialization1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_signals1.42.0", rpm:"libboost_signals1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost-static-devel", rpm:"libboost-static-devel~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_system1.42.0", rpm:"libboost_system1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_thread1.42.0", rpm:"libboost_thread1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_unit_test_framework1.42.0", rpm:"libboost_unit_test_framework1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_wave1.42.0", rpm:"libboost_wave1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libboost_wserialization1.42.0", rpm:"libboost_wserialization1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"boost", rpm:"boost~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_date_time1.42.0", rpm:"lib64boost_date_time1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost-devel", rpm:"lib64boost-devel~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost-devel-doc", rpm:"lib64boost-devel-doc~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_filesystem1.42.0", rpm:"lib64boost_filesystem1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_graph1.42.0", rpm:"lib64boost_graph1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_iostreams1.42.0", rpm:"lib64boost_iostreams1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_math_c99", rpm:"lib64boost_math_c99~1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_math_c99f1.42.0", rpm:"lib64boost_math_c99f1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_math_c99l1.42.0", rpm:"lib64boost_math_c99l1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_math_tr1", rpm:"lib64boost_math_tr1~1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_math_tr1f1.42.0", rpm:"lib64boost_math_tr1f1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_math_tr1l1.42.0", rpm:"lib64boost_math_tr1l1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_prg_exec_monitor1.42.0", rpm:"lib64boost_prg_exec_monitor1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_program_options1.42.0", rpm:"lib64boost_program_options1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_python1.42.0", rpm:"lib64boost_python1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_regex1.42.0", rpm:"lib64boost_regex1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_serialization1.42.0", rpm:"lib64boost_serialization1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_signals1.42.0", rpm:"lib64boost_signals1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost-static-devel", rpm:"lib64boost-static-devel~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_system1.42.0", rpm:"lib64boost_system1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_thread1.42.0", rpm:"lib64boost_thread1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_unit_test_framework1.42.0", rpm:"lib64boost_unit_test_framework1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_wave1.42.0", rpm:"lib64boost_wave1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64boost_wserialization1.42.0", rpm:"lib64boost_wserialization1.42.0~1.42.0~3.2mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
