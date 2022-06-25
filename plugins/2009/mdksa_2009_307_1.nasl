# OpenVAS Vulnerability Test
# $Id: mdksa_2009_307_1.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:307-1 (libtool)
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
tag_insight = "A vulnerability was discovered and corrected in libtool:

All versions of libtool prior to 2.2.6b suffers from a local
privilege escalation vulnerability that could be exploited under
certain conditions to load arbitrary code (CVE-2009-3736).

This advisory fixes this issue. Additionally, all applications
embedding the libtool code were patched in order to avoid possible
future exploitations of this issue.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:307-1";
tag_summary = "The remote host is missing an update to libtool
announced via advisory MDVSA-2009:307-1.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.311645");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
 script_cve_id("CVE-2009-3736");
 script_tag(name:"cvss_base", value:"6.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:307-1 (libtool)");



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
if ((res = isrpmvuln(pkg:"arts", rpm:"arts~1.5.7~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc", rpm:"gcc~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-c++", rpm:"gcc-c++~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-cpp", rpm:"gcc-cpp~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-doc", rpm:"gcc-doc~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-doc-pdf", rpm:"gcc-doc-pdf~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-gfortran", rpm:"gcc-gfortran~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-gnat", rpm:"gcc-gnat~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-java", rpm:"gcc-java~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-objc", rpm:"gcc-objc~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcc-objc++", rpm:"gcc-objc++~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gcj-tools", rpm:"gcj-tools~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"heartbeat", rpm:"heartbeat~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"heartbeat-ldirectord", rpm:"heartbeat-ldirectord~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"heartbeat-pils", rpm:"heartbeat-pils~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"heartbeat-stonith", rpm:"heartbeat-stonith~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.3.2.9~10.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.3.2.9~10.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.3.2.9~10.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libarts1", rpm:"libarts1~1.5.7~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libarts1-devel", rpm:"libarts1-devel~1.5.7~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffi4", rpm:"libffi4~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffi-devel", rpm:"libffi-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcc1", rpm:"libgcc1~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcj8", rpm:"libgcj8~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcj8-base", rpm:"libgcj8-base~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcj8-src", rpm:"libgcj8-src~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcj-devel", rpm:"libgcj-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgcj-static-devel", rpm:"libgcj-static-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgfortran2", rpm:"libgfortran2~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgnat1", rpm:"libgnat1~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgomp1", rpm:"libgomp1~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgomp-devel", rpm:"libgomp-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libheartbeat1", rpm:"libheartbeat1~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libheartbeat1-devel", rpm:"libheartbeat1-devel~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libheartbeat-apphb0", rpm:"libheartbeat-apphb0~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libheartbeat-pils1", rpm:"libheartbeat-pils1~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libheartbeat-pils1-devel", rpm:"libheartbeat-pils1-devel~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libheartbeat-stonith1", rpm:"libheartbeat-stonith1~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libheartbeat-stonith1-devel", rpm:"libheartbeat-stonith1-devel~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libltdl3", rpm:"libltdl3~1.5.22~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libltdl3-devel", rpm:"libltdl3-devel~1.5.22~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick10.7.0", rpm:"libmagick10.7.0~6.3.2.9~10.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick10.7.0-devel", rpm:"libmagick10.7.0-devel~6.3.2.9~10.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmudflap0", rpm:"libmudflap0~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmudflap-devel", rpm:"libmudflap-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libobjc2", rpm:"libobjc2~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libprelude2", rpm:"libprelude2~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libprelude-devel", rpm:"libprelude-devel~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libprelude-static-devel", rpm:"libprelude-static-devel~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libstdc++6", rpm:"libstdc++6~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libstdc++-devel", rpm:"libstdc++-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libstdc++-static-devel", rpm:"libstdc++-static-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtool", rpm:"libtool~1.5.22~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtool-base", rpm:"libtool-base~1.5.22~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtunepimp5", rpm:"libtunepimp5~0.5.3~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtunepimp-devel", rpm:"libtunepimp-devel~0.5.3~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.3.2.9~10.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-prelude", rpm:"perl-prelude~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"prelude-tools", rpm:"prelude-tools~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-devel", rpm:"proftpd-devel~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_autohost", rpm:"proftpd-mod_autohost~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_ban", rpm:"proftpd-mod_ban~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_case", rpm:"proftpd-mod_case~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_ctrls_admin", rpm:"proftpd-mod_ctrls_admin~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_gss", rpm:"proftpd-mod_gss~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_ifsession", rpm:"proftpd-mod_ifsession~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_ldap", rpm:"proftpd-mod_ldap~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_load", rpm:"proftpd-mod_load~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab", rpm:"proftpd-mod_quotatab~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_file", rpm:"proftpd-mod_quotatab_file~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_ldap", rpm:"proftpd-mod_quotatab_ldap~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_radius", rpm:"proftpd-mod_quotatab_radius~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_sql", rpm:"proftpd-mod_quotatab_sql~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_radius", rpm:"proftpd-mod_radius~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_ratio", rpm:"proftpd-mod_ratio~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_rewrite", rpm:"proftpd-mod_rewrite~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_shaper", rpm:"proftpd-mod_shaper~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_site_misc", rpm:"proftpd-mod_site_misc~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_sql", rpm:"proftpd-mod_sql~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_sql_mysql", rpm:"proftpd-mod_sql_mysql~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_sql_postgres", rpm:"proftpd-mod_sql_postgres~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_time", rpm:"proftpd-mod_time~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_tls", rpm:"proftpd-mod_tls~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_wrap", rpm:"proftpd-mod_wrap~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_wrap_file", rpm:"proftpd-mod_wrap_file~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"proftpd-mod_wrap_sql", rpm:"proftpd-mod_wrap_sql~1.3.2~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-prelude", rpm:"python-prelude~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-tunepimp", rpm:"python-tunepimp~0.5.3~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"smalltalk", rpm:"smalltalk~2.3.3~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tunepimp-plugins", rpm:"tunepimp-plugins~0.5.3~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tunepimp-utils", rpm:"tunepimp-utils~0.5.3~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64arts1", rpm:"lib64arts1~1.5.7~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64arts1-devel", rpm:"lib64arts1-devel~1.5.7~2.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gcj8", rpm:"lib64gcj8~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gcj-devel", rpm:"lib64gcj-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gcj-static-devel", rpm:"lib64gcj-static-devel~4.2.2~3.2mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64heartbeat1", rpm:"lib64heartbeat1~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64heartbeat1-devel", rpm:"lib64heartbeat1-devel~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64heartbeat-apphb0", rpm:"lib64heartbeat-apphb0~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64heartbeat-pils1", rpm:"lib64heartbeat-pils1~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64heartbeat-pils1-devel", rpm:"lib64heartbeat-pils1-devel~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64heartbeat-stonith1", rpm:"lib64heartbeat-stonith1~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64heartbeat-stonith1-devel", rpm:"lib64heartbeat-stonith1-devel~2.0.8~4.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ltdl3", rpm:"lib64ltdl3~1.5.22~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ltdl3-devel", rpm:"lib64ltdl3-devel~1.5.22~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick10.7.0", rpm:"lib64magick10.7.0~6.3.2.9~10.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick10.7.0-devel", rpm:"lib64magick10.7.0-devel~6.3.2.9~10.5mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64prelude2", rpm:"lib64prelude2~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64prelude-devel", rpm:"lib64prelude-devel~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64prelude-static-devel", rpm:"lib64prelude-static-devel~0.9.15.2~1.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64tunepimp5", rpm:"lib64tunepimp5~0.5.3~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64tunepimp-devel", rpm:"lib64tunepimp-devel~0.5.3~5.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
