# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1466");
  script_version("2020-04-16T05:56:07+0000");
  script_cve_id("CVE-2017-12451", "CVE-2017-12452", "CVE-2017-12799", "CVE-2017-12967", "CVE-2017-13710", "CVE-2017-14128", "CVE-2017-14129", "CVE-2017-14529", "CVE-2017-14930", "CVE-2017-14932", "CVE-2017-14934", "CVE-2017-14938", "CVE-2017-14939", "CVE-2017-14940", "CVE-2017-15021", "CVE-2017-15022", "CVE-2017-15024", "CVE-2017-15025", "CVE-2017-15225", "CVE-2017-15938", "CVE-2017-15939", "CVE-2017-15996", "CVE-2017-16832", "CVE-2017-17080", "CVE-2017-17121", "CVE-2017-17122", "CVE-2017-17123", "CVE-2017-17124", "CVE-2017-17125", "CVE-2017-7209", "CVE-2017-7299", "CVE-2017-7300", "CVE-2017-7301", "CVE-2017-7302", "CVE-2017-7303", "CVE-2017-7304", "CVE-2017-7614", "CVE-2017-8393", "CVE-2017-8394", "CVE-2017-8395", "CVE-2017-8396", "CVE-2017-8397", "CVE-2017-8398", "CVE-2017-9038", "CVE-2017-9039", "CVE-2017-9040", "CVE-2017-9041", "CVE-2017-9042", "CVE-2017-9742", "CVE-2017-9744", "CVE-2017-9745", "CVE-2017-9746", "CVE-2017-9747", "CVE-2017-9748", "CVE-2017-9749", "CVE-2017-9750", "CVE-2017-9751", "CVE-2017-9752", "CVE-2017-9753", "CVE-2017-9754", "CVE-2017-9755", "CVE-2017-9756", "CVE-2017-9954", "CVE-2017-9955", "CVE-2018-12697", "CVE-2018-17358", "CVE-2018-17359", "CVE-2018-17360", "CVE-2018-18483", "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-19931", "CVE-2018-20657", "CVE-2018-6323", "CVE-2019-1010180", "CVE-2019-1010204", "CVE-2019-12972", "CVE-2019-14250", "CVE-2019-17451", "CVE-2019-9070", "CVE-2019-9071", "CVE-2019-9074", "CVE-2019-9075", "CVE-2019-9076");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 05:56:07 +0000 (Thu, 16 Apr 2020)");
  script_name("Huawei EulerOS: Security Advisory for binutils (EulerOS-SA-2020-1466)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.2\.2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1466");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'binutils' package(s) announced via the EulerOS-SA-2020-1466 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU Binutils 2017-04-03 allows remote attackers to cause a denial of service (NULL pointer dereference and application crash), related to the process_mips_specific function in readelf.c, via a crafted ELF file that triggers a large memory-allocation attempt.(CVE-2017-9040)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, has an aout_link_add_symbols function in bfd/aoutx.h that is vulnerable to a heap-based buffer over-read (off-by-one) because of an incomplete check for invalid string offsets while loading symbols, leading to a GNU linker (ld) program crash.(CVE-2017-7300)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, has an aout_link_add_symbols function in bfd/aoutx.h that has an off-by-one vulnerability because it does not carefully check the string offset. The vulnerability could lead to a GNU linker (ld) program crash.(CVE-2017-7301)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, has a swap_std_reloc_out function in bfd/aoutx.h that is vulnerable to an invalid read (of size 4) because of missing checks for relocs that could not be recognised. This vulnerability causes Binutils utilities like strip to crash.(CVE-2017-7302)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable to an invalid read (of size 4) because of missing a check (in the find_link function) for null headers before attempting to match them. This vulnerability causes Binutils utilities like strip to crash.(CVE-2017-7303)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable to an invalid read (of size 8) because of missing a check (in the copy_special_section_fields function) for an invalid sh_link field before attempting to follow it. This vulnerability causes Binutils utilities like strip to crash.(CVE-2017-7304)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable to a global buffer over-read error because of an assumption made by code that runs for objcopy and strip, that SHT_REL/SHR_RELA sections are always named starting with a .rel/.rela prefix. This vulnerability causes programs that conduct an analysis of binary programs using the libbfd library, such as objcopy and strip, to crash.(CVE-2017-8393)

The Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU Binutils 2.28, is vulnerable to an invalid write of size 8 because of missing a malloc() return-value check to see if memory had  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'binutils' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

if(release == "EULEROSVIRT-3.0.2.2") {

  if(!isnull(res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.27~28.base.1.h40.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);