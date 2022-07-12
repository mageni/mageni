# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0169");
  script_cve_id("CVE-2014-9939", "CVE-2016-4487", "CVE-2016-4488", "CVE-2016-4489", "CVE-2016-4490", "CVE-2016-4492", "CVE-2016-4493", "CVE-2016-6131", "CVE-2017-12448", "CVE-2017-12449", "CVE-2017-12450", "CVE-2017-12451", "CVE-2017-12452", "CVE-2017-12453", "CVE-2017-12454", "CVE-2017-12455", "CVE-2017-12456", "CVE-2017-12457", "CVE-2017-12458", "CVE-2017-12459", "CVE-2017-12799", "CVE-2017-13710", "CVE-2017-13716", "CVE-2017-13757", "CVE-2017-14128", "CVE-2017-14129", "CVE-2017-14130", "CVE-2017-14333", "CVE-2017-14529", "CVE-2017-14729", "CVE-2017-14745", "CVE-2017-14938", "CVE-2017-14939", "CVE-2017-14940", "CVE-2017-14974", "CVE-2017-15020", "CVE-2017-15021", "CVE-2017-15022", "CVE-2017-15023", "CVE-2017-15024", "CVE-2017-15025", "CVE-2017-15938", "CVE-2017-15939", "CVE-2017-6965", "CVE-2017-6966", "CVE-2017-6969", "CVE-2017-7209", "CVE-2017-7210", "CVE-2017-7223", "CVE-2017-7224", "CVE-2017-7225", "CVE-2017-7226", "CVE-2017-7227", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7302", "CVE-2017-7303", "CVE-2017-7304", "CVE-2017-7614", "CVE-2017-8392", "CVE-2017-8393", "CVE-2017-8394", "CVE-2017-8395", "CVE-2017-8396", "CVE-2017-8397", "CVE-2017-8398", "CVE-2017-8421", "CVE-2017-9038", "CVE-2017-9039", "CVE-2017-9040", "CVE-2017-9041", "CVE-2017-9042", "CVE-2017-9043", "CVE-2017-9044", "CVE-2017-9746", "CVE-2017-9747", "CVE-2017-9748", "CVE-2017-9750", "CVE-2017-9755", "CVE-2017-9756", "CVE-2017-9954", "CVE-2017-9955", "CVE-2018-10372", "CVE-2018-10373", "CVE-2018-10534", "CVE-2018-10535", "CVE-2018-18484", "CVE-2018-18700", "CVE-2018-6323", "CVE-2018-6543", "CVE-2018-6759", "CVE-2018-6872", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7570", "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945", "CVE-2019-9071", "CVE-2019-9073", "CVE-2019-9074", "CVE-2019-9075", "CVE-2019-9077");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-22 19:12:00 +0000 (Wed, 22 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2019-0169)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0169");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0169.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18987");
  script_xref(name:"URL", value:"https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob_plain;f=binutils/NEWS;hb=refs/tags/binutils-2_32");
  script_xref(name:"URL", value:"https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob_plain;f=gas/NEWS;hb=refs/tags/binutils-2_32");
  script_xref(name:"URL", value:"https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=blob_plain;f=ld/NEWS;hb=refs/tags/binutils-2_32");
  script_xref(name:"URL", value:"https://lwn.net/Alerts/694764/");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/03/16/8");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/04/10/16");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/05/18/7");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/09/26/6");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/09/30/1");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/09/30/2");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/09/30/3");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/10/04/3");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/10/04/6");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/10/04/4");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/10/04/5");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/10/04/8");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/10/04/7");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/10/27/4");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2017/10/27/3");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-12/msg00008.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004678.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-October/004683.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-10/msg00104.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-10/msg00133.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/37N6SA4WSBTFWAMPQXHSO7JRJQ6EIIO5/");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1645958");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the MGASA-2019-0169 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides the latest stable binutils, currently version 2.32
and fixes at least the following security issues:

ihex.c in GNU Binutils before 2.26 contains a stack buffer overflow when
printing bad bytes in Intel Hex objects (CVE-2014-9939)

Use-after-free vulnerability in libiberty allows remote attackers to cause
a denial of service (segmentation fault and crash) via a crafted binary,
related to 'btypevec.' (CVE-2016-4487)

Use-after-free vulnerability in libiberty allows remote attackers to cause
a denial of service (segmentation fault and crash) via a crafted binary,
related to 'ktypevec.' (CVE-2016-4488)

Integer overflow in the gnu_special function in libiberty allows remote
attackers to cause a denial of service (segmentation fault and crash) via
a crafted binary, related to the 'demangling of virtual tables.'
(CVE-2016-4489)

Integer overflow in cp-demangle.c in libiberty allows remote attackers to
cause a denial of service (segmentation fault and crash) via a crafted
binary, related to inconsistent use of the long and int types for lengths.
(CVE-2016-4490)

Buffer overflow in the do_type function in cplus-dem.c in libiberty allows
remote attackers to cause a denial of service (segmentation fault and
crash) via a crafted binary. (CVE-2016-4492)

The demangle_template_value_parm and do_hpacc_template_literal functions
in cplus-dem.c in libiberty allow remote attackers to cause a denial of
service (out-of-bounds read and crash) via a crafted binary.
(CVE-2016-4493)

The demangler in GNU Libiberty allows remote attackers to cause a denial
of service (infinite loop, stack overflow, and crash) via a cycle in the
references of remembered mangled types. (CVE-2016-6131)

readelf in GNU Binutils 2.28 writes to illegal addresses while processing
corrupt input files containing symbol-difference relocations, leading to
a heap-based buffer overflow. (CVE-2017-6965)

readelf in GNU Binutils 2.28 has a use-after-free (specifically
read-after-free) error while processing multiple, relocated sections in an
MSP430 binary. This is caused by mishandling of an invalid symbol index,
and mishandling of state across invocations. (CVE-2017-6966)

readelf in GNU Binutils 2.28 is vulnerable to a heap-based buffer over-read
while processing corrupt RL78 binaries. The vulnerability can trigger
program crashes. It may lead to an information leak as well. (CVE-2017-6969)

The dump_section_as_bytes function in readelf in GNU Binutils 2.28 accesses
a NULL pointer while reading section contents in a corrupt binary, leading
to a program crash. (CVE-2017-7209)

objdump in GNU Binutils 2.28 is vulnerable to multiple heap-based buffer
over-reads (of size 1 and size 8) while handling corrupt STABS enum type
strings in a crafted object file, leading to program crash. (CVE-2017-7210)

GNU assembler in GNU Binutils 2.28 is vulnerable to a global buffer
overflow (of size 1) while attempting to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'binutils' package(s) on Mageia 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.32~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64binutils-devel", rpm:"lib64binutils-devel~2.32~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbinutils-devel", rpm:"libbinutils-devel~2.32~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
