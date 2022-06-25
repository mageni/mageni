# OpenVAS Vulnerability Test
# $Id: mdksa_2009_297.nasl 6573 2017-07-06 13:10:50Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:297 (ffmpeg)
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
tag_insight = "Vulnerabilities have been discovered and corrected in ffmpeg:

- The ffmpeg lavf demuxer allows user-assisted attackers to cause
a denial of service (application crash) via a crafted GIF file
(CVE-2008-3230)

- FFmpeg 0.4.9, as used by MPlayer, allows context-dependent attackers
to cause a denial of service (memory consumption) via unknown vectors,
aka a Tcp/udp memory leak. (CVE-2008-4869)

- Integer signedness error in the fourxm_read_header function in
libavformat/4xm.c in FFmpeg before revision 16846 allows remote
attackers to execute arbitrary code via a malformed 4X movie file with
a large current_track value, which triggers a NULL pointer dereference
(CVE-2009-0385)

The updated packages fix this issue.

Affected: 2009.0, Corporate 3.0, Corporate 4.0, Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:297";
tag_summary = "The remote host is missing an update to ffmpeg
announced via advisory MDVSA-2009:297.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.305175");
 script_version("$Revision: 6573 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:10:50 +0200 (Thu, 06 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-11-17 21:42:12 +0100 (Tue, 17 Nov 2009)");
 script_cve_id("CVE-2008-3230", "CVE-2008-4869", "CVE-2009-0385");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Mandriva Security Advisory MDVSA-2009:297 (ffmpeg)");



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
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavformats52", rpm:"libavformats52~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavutil49", rpm:"libavutil49~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg51", rpm:"libffmpeg51~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libswscaler0", rpm:"libswscaler0~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avformats52", rpm:"lib64avformats52~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avutil49", rpm:"lib64avutil49~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg51", rpm:"lib64ffmpeg51~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64swscaler0", rpm:"lib64swscaler0~0.4.9~3.pre1.14161.1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.8~7.4.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg0", rpm:"libffmpeg0~0.4.8~7.4.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg0-devel", rpm:"libffmpeg0-devel~0.4.8~7.4.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg0", rpm:"lib64ffmpeg0~0.4.8~7.4.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg0-devel", rpm:"lib64ffmpeg0-devel~0.4.8~7.4.C30mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.9~0.pre1.5.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg0", rpm:"libffmpeg0~0.4.9~0.pre1.5.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg0-devel", rpm:"libffmpeg0-devel~0.4.9~0.pre1.5.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg0", rpm:"lib64ffmpeg0~0.4.9~0.pre1.5.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg0-devel", rpm:"lib64ffmpeg0-devel~0.4.9~0.pre1.5.4.20060mlcs4", rls:"MNDK_4.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavformats52", rpm:"libavformats52~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libavutil49", rpm:"libavutil49~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg51", rpm:"libffmpeg51~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libswscaler0", rpm:"libswscaler0~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avformats52", rpm:"lib64avformats52~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64avutil49", rpm:"lib64avutil49~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg51", rpm:"lib64ffmpeg51~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64swscaler0", rpm:"lib64swscaler0~0.4.9~3.pre1.14161.1.2mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
