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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1390");
  script_version("2020-04-16T05:46:13+0000");
  script_cve_id("CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562", "CVE-2014-8716", "CVE-2014-9821", "CVE-2014-9822", "CVE-2014-9823", "CVE-2014-9824", "CVE-2014-9825", "CVE-2014-9837", "CVE-2014-9852", "CVE-2014-9853", "CVE-2014-9854", "CVE-2014-9907", "CVE-2015-8900", "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903", "CVE-2015-8957", "CVE-2015-8958", "CVE-2016-10046", "CVE-2016-10047", "CVE-2016-10049", "CVE-2016-10053", "CVE-2016-10054", "CVE-2016-10055", "CVE-2016-10056", "CVE-2016-10057", "CVE-2016-10058", "CVE-2016-10059", "CVE-2016-10060", "CVE-2016-10061", "CVE-2016-10062", "CVE-2016-10063", "CVE-2016-10064", "CVE-2016-10065", "CVE-2016-10066", "CVE-2016-10067", "CVE-2016-10068", "CVE-2016-10069", "CVE-2016-10070", "CVE-2016-10071", "CVE-2016-10144", "CVE-2016-10145", "CVE-2016-10252", "CVE-2016-4562", "CVE-2016-4563", "CVE-2016-4564", "CVE-2016-5687", "CVE-2016-5688", "CVE-2016-5689", "CVE-2016-5690", "CVE-2016-5691", "CVE-2016-6491", "CVE-2016-6823", "CVE-2016-7101", "CVE-2016-7515", "CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7518", "CVE-2016-7519", "CVE-2016-7520", "CVE-2016-7525", "CVE-2016-7526", "CVE-2016-7528", "CVE-2016-7529", "CVE-2016-7530", "CVE-2016-7531", "CVE-2016-7533", "CVE-2016-7534", "CVE-2016-7539", "CVE-2016-7799", "CVE-2016-7906", "CVE-2016-8677", "CVE-2016-8707", "CVE-2016-8866", "CVE-2016-9559", "CVE-2017-11478", "CVE-2017-11505", "CVE-2017-11523", "CVE-2017-11524", "CVE-2017-11525", "CVE-2017-11526", "CVE-2017-11527", "CVE-2017-11528", "CVE-2017-11529", "CVE-2017-11530", "CVE-2017-12427", "CVE-2017-13139", "CVE-2017-13140", "CVE-2017-13141", "CVE-2017-13142", "CVE-2017-13143", "CVE-2017-13144", "CVE-2017-13145", "CVE-2017-13146", "CVE-2017-13658", "CVE-2017-17499", "CVE-2017-17504", "CVE-2017-5507", "CVE-2017-5508", "CVE-2017-5509", "CVE-2017-5510", "CVE-2017-6497", "CVE-2017-6498", "CVE-2017-6499", "CVE-2017-6500", "CVE-2017-6501", "CVE-2017-6502", "CVE-2017-7941", "CVE-2017-7942", "CVE-2017-7943", "CVE-2018-16323", "CVE-2018-16328", "CVE-2018-20467", "CVE-2018-6405", "CVE-2019-13133", "CVE-2019-13134");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 05:46:13 +0000 (Thu, 16 Apr 2020)");
  script_name("Huawei EulerOS: Security Advisory for ImageMagick (EulerOS-SA-2020-1390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP3");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1390");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'ImageMagick' package(s) announced via the EulerOS-SA-2020-1390 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The HorizontalFilter function in resize.c in ImageMagick before 6.8.9-9 allows remote attackers to cause a denial of service (out-of-bounds read) via a crafted image file.(CVE-2014-8354)

PCX parser code in ImageMagick before 6.8.9-9 allows remote attackers to cause a denial of service (out-of-bounds read).(CVE-2014-8355)

DCM decode in ImageMagick before 6.8.9-9 allows remote attackers to cause a denial of service (out-of-bounds read).(CVE-2014-8562)

The JPEG decoder in ImageMagick before 6.8.9-9 allows local users to cause a denial of service (out-of-bounds memory access and crash).(CVE-2014-8716)

Heap-based buffer overflow in ImageMagick allows remote attackers to have unspecified impact via a crafted xpm file.(CVE-2014-9821)

Heap-based buffer overflow in ImageMagick allows remote attackers to have unspecified impact via a crafted quantum file.(CVE-2014-9822)

Heap-based buffer overflow in ImageMagick allows remote attackers to have unspecified impact via a crafted palm file, a different vulnerability than CVE-2014-9819.(CVE-2014-9823)

Heap-based buffer overflow in ImageMagick allows remote attackers to have unspecified impact via a crafted psd file, a different vulnerability than CVE-2014-9825.(CVE-2014-9824)

Heap-based buffer overflow in ImageMagick allows remote attackers to have unspecified impact via a crafted psd file, a different vulnerability than CVE-2014-9824.(CVE-2014-9825)

coders/pnm.c in ImageMagick 6.9.0-1 Beta and earlier allows remote attackers to cause a denial of service (crash) via a crafted png file.(CVE-2014-9837)

distribute-cache.c in ImageMagick re-uses objects after they have been destroyed, which allows remote attackers to have unspecified impact via unspecified vectors.(CVE-2014-9852)

Memory leak in coders/rle.c in ImageMagick allows remote attackers to cause a denial of service (memory consumption) via a crafted rle file.(CVE-2014-9853)

coders/tiff.c in ImageMagick allows remote attackers to cause a denial of service (application crash) via vectors related to the ''identification of image.''(CVE-2014-9854)

coders/dds.c in ImageMagick allows remote attackers to cause a denial of service via a crafted DDS file.(CVE-2014-9907)

The ReadHDRImage function in coders/hdr.c in ImageMagick 6.x and 7.x allows remote attackers to cause a denial of service (infinite loop) via a crafted HDR file.(CVE-2015-8900)

ImageMagick 6.x before 6.9.0-5 Beta allows remote attackers to cause a denial of service (infinite loop) via a crafted MIFF file.(CVE-2015-8901)

The ReadBlobByte function in coders/pdb.c in ImageMagick 6.x before 6.9.0-5 Beta allows remote attackers  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.9.9.38~1.h6", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.9.9.38~1.h6", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-libs", rpm:"ImageMagick-libs~6.9.9.38~1.h6", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.9.9.38~1.h6", rls:"EULEROS-2.0SP3"))) {
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