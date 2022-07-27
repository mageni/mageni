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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0212");
  script_cve_id("CVE-2017-11704", "CVE-2017-11728", "CVE-2017-11729", "CVE-2017-11730", "CVE-2017-11731", "CVE-2017-11732", "CVE-2017-11733", "CVE-2017-11734", "CVE-2017-16883", "CVE-2017-16898", "CVE-2017-8782", "CVE-2017-9988", "CVE-2017-9989", "CVE-2018-5251", "CVE-2018-5294", "CVE-2018-6315", "CVE-2018-6359");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-26 12:41:00 +0000 (Fri, 26 Apr 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0212)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0212");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0212.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22815");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ming' package(s) announced via the MGASA-2018-0212 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The readString function in util/read.c and util/old/read.c in libming
0.4.8 allows remote attackers to cause a denial of service via a large
file that is mishandled by listswf, listaction, etc. This occurs
because of an integer overflow that leads to a memory allocation error.
(CVE-2017-8782)

The readEncUInt30 function in util/read.c in libming 0.4.8 mishandles
memory allocation. A crafted input will lead to a remote denial of
service (NULL pointer dereference) attack against parser.c.
(CVE-2017-9988)

util/outputtxt.c in libming 0.4.8 mishandles memory allocation. A
crafted input will lead to a remote denial of service (NULL pointer
dereference) attack. (CVE-2017-9989)

A heap-based buffer over-read was found in the function decompileIF in
util/decompile.c in Ming 0.4.8, which allows attackers to cause a denial
of service via a crafted file. (CVE-2017-11704)

A heap-based buffer over-read was found in the function OpCode (called
from decompileSETMEMBER) in util/decompile.c in Ming 0.4.8, which allows
attackers to cause a denial of service via a crafted file.
(CVE-2017-11728)

A heap-based buffer over-read was found in the function OpCode (called
from decompileINCR_DECR line 1440) in util/decompile.c in Ming 0.4.8,
which allows attackers to cause a denial of service via a crafted file.
(CVE-2017-11729)

A heap-based buffer over-read was found in the function OpCode (called
from decompileINCR_DECR line 1474) in util/decompile.c in Ming 0.4.8,
which allows attackers to cause a denial of service via a crafted file.
(CVE-2017-11730)

An invalid memory read vulnerability was found in the function OpCode
(called from isLogicalOp and decompileIF) in util/decompile.c in Ming
0.4.8, which allows attackers to cause a denial of service via a crafted
file. (CVE-2017-11731)

A heap-based buffer overflow vulnerability was found in the function
dcputs (called from decompileIMPLEMENTS) in util/decompile.c in Ming
0.4.8, which allows attackers to cause a denial of service via a
crafted file. (CVE-2017-11732)

A null pointer dereference vulnerability was found in the function
stackswap (called from decompileSTACKSWAP) in util/decompile.c in Ming
0.4.8, which allows attackers to cause a denial of service via a crafted
file. (CVE-2017-11733)

A heap-based buffer over-read was found in the function
decompileCALLFUNCTION in util/decompile.c in Ming 0.4.8, which allows
attackers to cause a denial of service via a crafted file.
(CVE-2017-11734)

The outputSWF_TEXT_RECORD function in util/outputscript.c in libming <=
0.4.8 is vulnerable to a NULL pointer dereference, which may allow
attackers to cause a denial of service via a crafted swf file.
(CVE-2017-16883)

The printMP3Headers function in util/listmp3.c in libming v0.4.8 or
earlier is vulnerable to a global buffer overflow, which may allow
attackers to cause a denial of service via a crafted file, a different
vulnerability than ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ming' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ming-devel", rpm:"lib64ming-devel~0.4.5~14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ming1", rpm:"lib64ming1~0.4.5~14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libming-devel", rpm:"libming-devel~0.4.5~14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libming1", rpm:"libming1~0.4.5~14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ming", rpm:"ming~0.4.5~14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ming-utils", rpm:"ming-utils~0.4.5~14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SWF", rpm:"perl-SWF~0.4.5~14.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-SWF", rpm:"python-SWF~0.4.5~14.1.mga6", rls:"MAGEIA6"))) {
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
