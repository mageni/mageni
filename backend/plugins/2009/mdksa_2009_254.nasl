# OpenVAS Vulnerability Test
# $Id: mdksa_2009_254.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:254 (graphviz)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "A vulnerability was discovered and corrected in graphviz:

Stack-based buffer overflow in the push_subg function in parser.y
(lib/graph/parser.c) in Graphviz 2.20.2, and possibly earlier versions,
allows user-assisted remote attackers to cause a denial of service
(memory corruption) or execute arbitrary code via a DOT file with a
large number of Agraph_t elements (CVE-2008-4555).

This update provides a fix for this vulnerability.

Affected: 2008.1, 2009.0, Corporate 4.0, Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:254";
tag_summary = "The remote host is missing an update to graphviz
announced via advisory MDVSA-2009:254.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305180");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-06 02:49:40 +0200 (Tue, 06 Oct 2009)");
 script_cve_id("CVE-2008-4555");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:254 (graphviz)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz4", rpm:"libgraphviz4~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz-devel", rpm:"libgraphviz-devel~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizlua0", rpm:"libgraphvizlua0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizocaml0", rpm:"libgraphvizocaml0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizperl0", rpm:"libgraphvizperl0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizphp0", rpm:"libgraphvizphp0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizpython0", rpm:"libgraphvizpython0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizr0", rpm:"libgraphvizr0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizruby0", rpm:"libgraphvizruby0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz-static-devel", rpm:"libgraphviz-static-devel~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviztcl0", rpm:"libgraphviztcl0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz4", rpm:"lib64graphviz4~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz-devel", rpm:"lib64graphviz-devel~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizlua0", rpm:"lib64graphvizlua0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizocaml0", rpm:"lib64graphvizocaml0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizperl0", rpm:"lib64graphvizperl0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizphp0", rpm:"lib64graphvizphp0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizpython0", rpm:"lib64graphvizpython0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizr0", rpm:"lib64graphvizr0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizruby0", rpm:"lib64graphvizruby0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz-static-devel", rpm:"lib64graphviz-static-devel~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviztcl0", rpm:"lib64graphviztcl0~2.16.1~3.2mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz4", rpm:"libgraphviz4~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz-devel", rpm:"libgraphviz-devel~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizlua0", rpm:"libgraphvizlua0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizocaml0", rpm:"libgraphvizocaml0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizperl0", rpm:"libgraphvizperl0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizphp0", rpm:"libgraphvizphp0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizpython0", rpm:"libgraphvizpython0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizr0", rpm:"libgraphvizr0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizruby0", rpm:"libgraphvizruby0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz-static-devel", rpm:"libgraphviz-static-devel~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviztcl0", rpm:"libgraphviztcl0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz4", rpm:"lib64graphviz4~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz-devel", rpm:"lib64graphviz-devel~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizlua0", rpm:"lib64graphvizlua0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizocaml0", rpm:"lib64graphvizocaml0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizperl0", rpm:"lib64graphvizperl0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizphp0", rpm:"lib64graphvizphp0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizpython0", rpm:"lib64graphvizpython0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizr0", rpm:"lib64graphvizr0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizruby0", rpm:"lib64graphvizruby0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz-static-devel", rpm:"lib64graphviz-static-devel~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviztcl0", rpm:"lib64graphviztcl0~2.20.2~3.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz7", rpm:"libgraphviz7~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz7-devel", rpm:"libgraphviz7-devel~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviztcl7", rpm:"libgraphviztcl7~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviztcl7-devel", rpm:"libgraphviztcl7-devel~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz7", rpm:"lib64graphviz7~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz7-devel", rpm:"lib64graphviz7-devel~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviztcl7", rpm:"lib64graphviztcl7~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviztcl7-devel", rpm:"lib64graphviztcl7-devel~2.2.1~3.2.20060mdk", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz4", rpm:"libgraphviz4~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz-devel", rpm:"libgraphviz-devel~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizlua0", rpm:"libgraphvizlua0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizocaml0", rpm:"libgraphvizocaml0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizperl0", rpm:"libgraphvizperl0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizphp0", rpm:"libgraphvizphp0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizpython0", rpm:"libgraphvizpython0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizr0", rpm:"libgraphvizr0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizruby0", rpm:"libgraphvizruby0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz-static-devel", rpm:"libgraphviz-static-devel~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviztcl0", rpm:"libgraphviztcl0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz4", rpm:"lib64graphviz4~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz-devel", rpm:"lib64graphviz-devel~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizlua0", rpm:"lib64graphvizlua0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizocaml0", rpm:"lib64graphvizocaml0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizperl0", rpm:"lib64graphvizperl0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizphp0", rpm:"lib64graphvizphp0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizpython0", rpm:"lib64graphvizpython0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizr0", rpm:"lib64graphvizr0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizruby0", rpm:"lib64graphvizruby0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz-static-devel", rpm:"lib64graphviz-static-devel~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviztcl0", rpm:"lib64graphviztcl0~2.20.2~3.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
