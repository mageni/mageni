# OpenVAS Vulnerability Test
# $Id: mdksa_2009_286.nasl 6587 2017-07-07 06:35:35Z cfischer $
# Description: Auto-generated from advisory MDVSA-2009:286 (ocaml-camlimages)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in
ocaml-camlimages:

Multiple integer overflows in CamlImages 2.2 and earlier might allow
context-dependent attackers to execute arbitrary code via a crafted
PNG image with large width and height values that trigger a heap-based
buffer overflow in the (1) read_png_file or (2) read_png_file_as_rgb24
function (CVE-2009-2295).

Multiple integer overflows in CamlImages 2.2 might allow
context-dependent attackers to execute arbitrary code via images
containing large width and height values that trigger a heap-based
buffer overflow, related to (1) crafted GIF files (gifread.c) and
(2) crafted JPEG files (jpegread.c), a different vulnerability than
CVE-2009-2295 (CVE-2009-2660).

Multiple integer overflows in tiffread.c in CamlImages 2.2 might allow
remote attackers to execute arbitrary code via TIFF images containing
large width and height values that trigger heap-based buffer overflows
(CVE-2009-3296).

This update fixes these vulnerabilities.

Affected: Enterprise Server 5.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:286";
tag_summary = "The remote host is missing an update to ocaml-camlimages
announced via advisory MDVSA-2009:286.";

                                                                                

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.310502");
 script_version("$Revision: 6587 $");
 script_tag(name:"last_modification", value:"$Date: 2017-07-07 08:35:35 +0200 (Fri, 07 Jul 2017) $");
 script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
 script_cve_id("CVE-2009-2295", "CVE-2009-2660", "CVE-2009-3296");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Mandrake Security Advisory MDVSA-2009:286 (ocaml-camlimages)");



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
if ((res = isrpmvuln(pkg:"ocaml-camlimages", rpm:"ocaml-camlimages~2.20~13.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ocaml-camlimages-devel", rpm:"ocaml-camlimages-devel~2.20~13.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
