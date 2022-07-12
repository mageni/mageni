###############################################################################
# OpenVAS Vulnerability Test
#
# HP-UX Update for Java VM Classloader (J2SE) HPSBUX00295
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
tag_impact = "Remote increase of privileges
  unauthorized access
  arbitrary code execution.";
tag_affected = "Java VM Classloader (J2SE) on
  HP-UX B.11.00, B.11.04, B.11.11, B.11.22, B.11.23 running Java 1.2.X,";
tag_insight = "A vulnerability in the Java Runtime Environment (JRE) classloader can allow 
  an untrusted applet to escalate privileges including reading and writing 
  files and executing arbitrary code on client systems.";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://www11.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c00901838-1");
  script_oid("1.3.6.1.4.1.25623.1.0.311345");
  script_version("$Revision: 6584 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 16:13:23 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-05-05 12:14:23 +0200 (Tue, 05 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "HPSBUX", value: "00295");
  script_name( "HP-UX Update for Java VM Classloader (J2SE) HPSBUX00295");

  script_tag(name:"summary", value:"Check for the Version of Java VM Classloader (J2SE)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("HP-UX Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/hp_hp-ux", "ssh/login/release");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-hpux.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "HPUX11.00")
{

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1-1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1_1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Jre1-1.JAVA-JRE", revision:"1.2.", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-1.JAVA-PLUGIN", revision:"1.2.", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-2.JAVA2-PLUGIN", revision:"1.2.", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1-1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1_1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-DEMO", revision:"1.2.1.16", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JDK-BASE", revision:"1.2.1.16", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JPD-BASE", revision:"1.2.1.16", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JDK", revision:"1.2.1.16", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JPD", revision:"1.2.1.16", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_base.JAVA2-JRE-BASE", revision:"1.2.1.16", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_doc.JAVA2-JRE-DOC", revision:"1.2.1.16", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_perf.JAVA2-JRE", revision:"1.2.1.16", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-COM", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-DEMO", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-IPF32", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-COM", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-DEMO", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-IPF32", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA11", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA20", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-CL", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-HS", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-CL", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-HS", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-DEMO", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-JDK-BASE", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_perf.JAVA2-JDK", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-PlugIn13.JAVA2-PLUGIN", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_base.JAVA2-JRE-BASE", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_doc.JAVA2-JRE-DOC", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_perf.JAVA2-JRE", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-IPF32", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-PA11", revision:"1.3.1.11", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-IPF32", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-PA11", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-COM", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-DEMO", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF32", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF64", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA11", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20W", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PNV2", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PWV2", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32-HS", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64-HS", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11-HS", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20-HS", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W-HS", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2-H", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2-H", revision:"1.4.1.04", rls:"HPUX11.00")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.22")
{

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1-1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1_1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Jre1-1.JAVA-JRE", revision:"1.2.", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-1.JAVA-PLUGIN", revision:"1.2.", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-2.JAVA2-PLUGIN", revision:"1.2.", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1-1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1_1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-DEMO", revision:"1.2.1.16", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JDK-BASE", revision:"1.2.1.16", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JPD-BASE", revision:"1.2.1.16", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JDK", revision:"1.2.1.16", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JPD", revision:"1.2.1.16", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_base.JAVA2-JRE-BASE", revision:"1.2.1.16", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_doc.JAVA2-JRE-DOC", revision:"1.2.1.16", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_perf.JAVA2-JRE", revision:"1.2.1.16", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-COM", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-DEMO", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-IPF32", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-COM", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-DEMO", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-IPF32", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA11", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA20", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-CL", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-HS", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-CL", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-HS", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-DEMO", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-JDK-BASE", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_perf.JAVA2-JDK", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-PlugIn13.JAVA2-PLUGIN", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_base.JAVA2-JRE-BASE", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_doc.JAVA2-JRE-DOC", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_perf.JAVA2-JRE", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-IPF32", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-PA11", revision:"1.3.1.11", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-IPF32", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-PA11", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-COM", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-DEMO", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF32", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF64", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA11", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20W", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PNV2", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PWV2", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32-HS", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64-HS", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11-HS", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20-HS", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W-HS", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2-H", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2-H", revision:"1.4.1.04", rls:"HPUX11.22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.04")
{

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1-1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1_1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Jre1-1.JAVA-JRE", revision:"1.2.", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-1.JAVA-PLUGIN", revision:"1.2.", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-2.JAVA2-PLUGIN", revision:"1.2.", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1-1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1_1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-DEMO", revision:"1.2.1.16", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JDK-BASE", revision:"1.2.1.16", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JPD-BASE", revision:"1.2.1.16", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JDK", revision:"1.2.1.16", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JPD", revision:"1.2.1.16", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_base.JAVA2-JRE-BASE", revision:"1.2.1.16", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_doc.JAVA2-JRE-DOC", revision:"1.2.1.16", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_perf.JAVA2-JRE", revision:"1.2.1.16", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-COM", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-DEMO", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-IPF32", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-COM", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-DEMO", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-IPF32", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA11", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA20", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-CL", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-HS", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-CL", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-HS", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-DEMO", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-JDK-BASE", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_perf.JAVA2-JDK", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-PlugIn13.JAVA2-PLUGIN", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_base.JAVA2-JRE-BASE", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_doc.JAVA2-JRE-DOC", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_perf.JAVA2-JRE", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-IPF32", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-PA11", revision:"1.3.1.11", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-IPF32", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-PA11", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-COM", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-DEMO", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF32", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF64", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA11", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20W", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PNV2", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PWV2", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32-HS", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64-HS", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11-HS", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20-HS", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W-HS", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2-H", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2-H", revision:"1.4.1.04", rls:"HPUX11.04")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.11")
{

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1-1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1_1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Jre1-1.JAVA-JRE", revision:"1.2.", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-1.JAVA-PLUGIN", revision:"1.2.", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-2.JAVA2-PLUGIN", revision:"1.2.", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1-1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1_1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-DEMO", revision:"1.2.1.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JDK-BASE", revision:"1.2.1.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JPD-BASE", revision:"1.2.1.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JDK", revision:"1.2.1.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JPD", revision:"1.2.1.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_base.JAVA2-JRE-BASE", revision:"1.2.1.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_doc.JAVA2-JRE-DOC", revision:"1.2.1.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_perf.JAVA2-JRE", revision:"1.2.1.16", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-COM", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-DEMO", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-IPF32", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-COM", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-DEMO", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-IPF32", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA11", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA20", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-CL", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-HS", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-CL", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-HS", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-DEMO", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-JDK-BASE", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_perf.JAVA2-JDK", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-PlugIn13.JAVA2-PLUGIN", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_base.JAVA2-JRE-BASE", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_doc.JAVA2-JRE-DOC", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_perf.JAVA2-JRE", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-IPF32", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-PA11", revision:"1.3.1.11", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-IPF32", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-PA11", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-COM", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-DEMO", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF32", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF64", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA11", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20W", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PNV2", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PWV2", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32-HS", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64-HS", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11-HS", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20-HS", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W-HS", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2-H", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2-H", revision:"1.4.1.04", rls:"HPUX11.11")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "HPUX11.23")
{

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1-1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Dev-Kit1_1.JAVA-JDK", revision:"1.2.", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Jre1-1.JAVA-JRE", revision:"1.2.", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-1.JAVA-PLUGIN", revision:"1.2.", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-PlugIn1-2.JAVA2-PLUGIN", revision:"1.2.", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1-1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java-Runtime1_1.JAVA-RUN", revision:"1.2.", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-DEMO", revision:"1.2.1.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JDK-BASE", revision:"1.2.1.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_base.JAVA2-JPD-BASE", revision:"1.2.1.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JDK", revision:"1.2.1.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2JDK_perf.JAVA2-JPD", revision:"1.2.1.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_base.JAVA2-JRE-BASE", revision:"1.2.1.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_doc.JAVA2-JRE-DOC", revision:"1.2.1.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2RTE_perf.JAVA2-JRE", revision:"1.2.1.16", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-COM", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-DEMO", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk.JDK-IPF32", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-COM", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-DEMO", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-IPF32", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA11", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk13.JDK13-PA20", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre.JRE-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-CL", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-IPF32-HS", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-CL", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA11-HS", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-CL", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre13.JRE13-PA20-HS", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-DEMO", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_base.JAVA2-JDK-BASE", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-JDK13_perf.JAVA2-JDK", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-PlugIn13.JAVA2-PLUGIN", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_base.JAVA2-JRE-BASE", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_doc.JAVA2-JRE-DOC", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Java2-RTE13_perf.JAVA2-JRE", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-COM-DOC", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-IPF32", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi13.JPI13-PA11", revision:"1.3.1.11", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-IPF32", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jpi14.JPI14-PA11", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-COM", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-DEMO", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF32", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-IPF64", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA11", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PA20W", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PNV2", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jdk14.JDK14-PWV2", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-COM-DOC", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF32-HS", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-IPF64-HS", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA11-HS", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20-HS", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PA20W-HS", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PNV2-H", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = ishpuxpkgvuln(pkg:"Jre14.JRE14-PWV2-H", revision:"1.4.1.04", rls:"HPUX11.23")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
