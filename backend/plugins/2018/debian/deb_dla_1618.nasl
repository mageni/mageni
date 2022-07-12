###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1618.nasl 14270 2019-03-18 14:24:29Z cfischer $
#
# Auto-generated from advisory DLA 1618-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891618");
  script_version("$Revision: 14270 $");
  script_cve_id("CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-17456", "CVE-2017-17457",
                "CVE-2017-8361", "CVE-2017-8362", "CVE-2017-8363", "CVE-2017-8365", "CVE-2018-13139",
                "CVE-2018-19432", "CVE-2018-19661", "CVE-2018-19662");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1618-1] libsndfile security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:24:29 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-28 00:00:00 +0100 (Fri, 28 Dec 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00016.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"libsndfile on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1.0.25-9.1+deb8u2.

We recommend that you upgrade your libsndfile packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been found in libsndfile, the library for
reading and writing files containing sampled sound.

CVE-2017-8361

The flac_buffer_copy function (flac.c) is affected by a buffer
overflow. This vulnerability might be leveraged by remote attackers to
cause a denial of service, or possibly have unspecified other impact
via a crafted audio file.

CVE-2017-8362

The flac_buffer_copy function (flac.c) is affected by an out-of-bounds
read vulnerability. This flaw might be leveraged by remote attackers to
cause a denial of service via a crafted audio file.

CVE-2017-8363

The flac_buffer_copy function (flac.c) is affected by a heap based OOB
read vulnerability. This flaw might be leveraged by remote attackers to
cause a denial of service via a crafted audio file.

CVE-2017-8365

The i2les_array function (pcm.c) is affected by a global buffer
overflow. This vulnerability might be leveraged by remote attackers to
cause a denial of service, or possibly have unspecified other impact
via a crafted audio file.

CVE-2017-14245
CVE-2017-14246
CVE-2017-17456
CVE-2017-17457

The d2alaw_array() and d2ulaw_array() functions (src/ulaw.c and
src/alaw.c) are affected by an out-of-bounds read vulnerability. This
flaw might be leveraged by remote attackers to cause denial of service
or information disclosure via a crafted audio file.

CVE-2017-14634

The double64_init() function (double64.c) is affected by a
divide-by-zero error. This vulnerability might be leveraged by remote
attackers to cause denial of service via a crafted audio file.

CVE-2018-13139

The psf_memset function (common.c) is affected by a stack-based buffer
overflow. This vulnerability might be leveraged by remote attackers to
cause a denial of service, or possibly have unspecified other impact
via a crafted audio file. The vulnerability can be triggered by the
executable sndfile-deinterleave.

CVE-2018-19432

The sf_write_int function (src/sndfile.c) is affected by an
out-of-bounds read vulnerability. This flaw might be leveraged by
remote attackers to cause a denial of service via a crafted audio file.

CVE-2018-19661
CVE-2018-19662

The i2alaw_array() and i2ulaw_array() functions (src/ulaw.c and
src/alaw.c) are affected by an out-of-bounds read vulnerability. This
flaw might be leveraged by remote attackers to cause denial of service
or information disclosure via a crafted audio file.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libsndfile1", ver:"1.0.25-9.1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsndfile1-dbg", ver:"1.0.25-9.1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libsndfile1-dev", ver:"1.0.25-9.1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sndfile-programs", ver:"1.0.25-9.1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"sndfile-programs-dbg", ver:"1.0.25-9.1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}