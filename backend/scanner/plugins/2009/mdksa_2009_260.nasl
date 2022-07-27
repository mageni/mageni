# OpenVAS Vulnerability Test
# $Id: mdksa_2009_260.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:260 (imagemagick)
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
tag_insight = "A vulnerability has been found and corrected in ImageMagick,
which could lead to integer overflow in the XMakeImage function in
magick/xwindow.c, allowing remote attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a crafted
TIFF file, which triggers a buffer overflow (CVE-2009-1882).

This update fixes this vulnerability.

Affected: 2008.1, 2009.0, 2009.1, Corporate 3.0, Corporate 4.0,
          Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:260";
tag_summary = "The remote host is missing an update to imagemagick
announced via advisory MDVSA-2009:260.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.307409");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-13 18:25:40 +0200 (Tue, 13 Oct 2009)");
 script_cve_id("CVE-2009-1882");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_name("Mandrake Security Advisory MDVSA-2009:260 (imagemagick)");



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
if ((res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.3.8.9~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.3.8.9~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.3.8.9~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick1", rpm:"libmagick1~6.3.8.9~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.3.8.9~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.3.8.9~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick1", rpm:"lib64magick1~6.3.8.9~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.3.8.9~1.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.4.2.10~5.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.4.2.10~5.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.4.2.10~5.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick1", rpm:"libmagick1~6.4.2.10~5.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.4.2.10~5.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.4.2.10~5.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick1", rpm:"lib64magick1~6.4.2.10~5.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.4.2.10~5.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.5.0.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.5.0.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.5.0.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick2", rpm:"libmagick2~6.5.0.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.5.0.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.5.0.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick2", rpm:"lib64magick2~6.5.0.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.5.0.2~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~5.5.7.15~6.13.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~5.5.7.15~6.13.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick5.5.7", rpm:"libMagick5.5.7~5.5.7.15~6.13.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick5.5.7-devel", rpm:"libMagick5.5.7-devel~5.5.7.15~6.13.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Magick", rpm:"perl-Magick~5.5.7.15~6.13.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~5.5.7.15~6.3.100mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~5.5.7.15~6.3.100mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64Magick5.5.7", rpm:"lib64Magick5.5.7~5.5.7.15~6.3.100mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64Magick5.5.7-devel", rpm:"lib64Magick5.5.7-devel~5.5.7.15~6.3.100mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Magick", rpm:"perl-Magick~5.5.7.15~6.3.100mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.2.4.3~1.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.2.4.3~1.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick8.4.2", rpm:"libMagick8.4.2~6.2.4.3~1.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libMagick8.4.2-devel", rpm:"libMagick8.4.2-devel~6.2.4.3~1.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.2.4.3~1.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64Magick8.4.2", rpm:"lib64Magick8.4.2~6.2.4.3~1.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64Magick8.4.2-devel", rpm:"lib64Magick8.4.2-devel~6.2.4.3~1.9.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick", rpm:"imagemagick~6.4.2.10~5.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-desktop", rpm:"imagemagick-desktop~6.4.2.10~5.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"imagemagick-doc", rpm:"imagemagick-doc~6.4.2.10~5.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick1", rpm:"libmagick1~6.4.2.10~5.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libmagick-devel", rpm:"libmagick-devel~6.4.2.10~5.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Image-Magick", rpm:"perl-Image-Magick~6.4.2.10~5.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick1", rpm:"lib64magick1~6.4.2.10~5.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64magick-devel", rpm:"lib64magick-devel~6.4.2.10~5.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
