# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891689");
  script_version("$Revision: 14282 $");
  script_cve_id("CVE-2017-7608", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613",
                "CVE-2018-16062", "CVE-2018-18310", "CVE-2018-18520", "CVE-2018-18521", "CVE-2019-7149",
                "CVE-2019-7150", "CVE-2019-7665");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1689-1] elfutils security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:55:18 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-26 00:00:00 +0100 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00036.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"elfutils on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
0.159-4.2+deb8u1.

We recommend that you upgrade your elfutils packages.");
  script_tag(name:"summary", value:"Several issues in elfutils, a collection of utilities to handle ELF
objects, have been found either by fuzzing or by using an
AddressSanitizer.

CVE-2019-7665
Due to a heap-buffer-overflow problem in function elf32_xlatetom()
a crafted ELF input can cause segmentation faults.

CVE-2019-7150
Add sanity check for partial core file dynamic data read.

CVE-2019-7149
Due to a heap-buffer-overflow problem in function read_srclines()
a crafted ELF input can cause segmentation faults.

CVE-2018-18521
By using a crafted ELF file, containing a zero sh_entsize, a
divide-by-zero vulnerability could allow remote attackers to
cause a denial of service (application crash).

CVE-2018-18520
By fuzzing an Invalid Address Deference problem in function elf_end
has been found.

CVE-2018-18310
By fuzzing an Invalid Address Read problem in eu-stack has been
found.

CVE-2018-16062
By using an AddressSanitizer a heap-buffer-overflow has been found.

CVE-2017-7613
By using fuzzing it was found that an allocation failure was not
handled properly.

CVE-2017-7612
By using a crafted ELF file, containing an invalid sh_entsize, a
remote attackers could cause a denial of service (application crash).

CVE-2017-7611
By using a crafted ELF file a remote attackers could cause a denial
of service (application crash).

CVE-2017-7610
By using a crafted ELF file a remote attackers could cause a denial
of service (application crash).

CVE-2017-7608
By fuzzing a heap based buffer overflow has been detected.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"elfutils", ver:"0.159-4.2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libasm-dev", ver:"0.159-4.2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libasm1", ver:"0.159-4.2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libdw-dev", ver:"0.159-4.2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libdw1", ver:"0.159-4.2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libelf-dev", ver:"0.159-4.2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libelf1", ver:"0.159-4.2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}