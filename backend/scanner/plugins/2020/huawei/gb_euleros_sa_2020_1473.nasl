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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1473");
  script_version("2020-04-16T05:57:29+0000");
  script_cve_id("CVE-2014-1932", "CVE-2014-1933", "CVE-2014-3007", "CVE-2014-3589", "CVE-2016-0740", "CVE-2016-0775", "CVE-2016-2533", "CVE-2016-4009", "CVE-2016-9189", "CVE-2019-16865", "CVE-2020-5313");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-04-16 10:29:54 +0000 (Thu, 16 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 05:57:29 +0000 (Thu, 16 Apr 2020)");
  script_name("Huawei EulerOS: Security Advisory for python-pillow (EulerOS-SA-2020-1473)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-3\.0\.2\.2");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1473");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'python-pillow' package(s) announced via the EulerOS-SA-2020-1473 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pillow before 3.3.2 allows context-dependent attackers to obtain sensitive information by using the 'crafted image file' approach, related to an 'Integer Overflow' issue affecting the Image.core.map_buffer in map.c component.(CVE-2016-9189)

Buffer overflow in the ImagingPcdDecode function in PcdDecode.c in Pillow before 3.1.1 and Python Imaging Library (PIL) 1.1.7 and earlier allows remote attackers to cause a denial of service (crash) via a crafted PhotoCD file.(CVE-2016-2533)

Buffer overflow in the ImagingFliDecode function in libImaging/FliDecode.c in Pillow before 3.1.1 allows remote attackers to cause a denial of service (crash) via a crafted FLI file.(CVE-2016-0775)

Buffer overflow in the ImagingLibTiffDecode function in libImaging/TiffDecode.c in Pillow before 3.1.1 allows remote attackers to overwrite memory via a crafted TIFF file.(CVE-2016-0740)

Integer overflow in the ImagingResampleHorizontal function in libImaging/Resample.c in Pillow before 3.1.1 allows remote attackers to have unspecified impact via negative values of the new size, which triggers a heap-based buffer overflow.(CVE-2016-4009)

PIL/IcnsImagePlugin.py in Python Imaging Library (PIL) and Pillow before 2.3.2 and 2.5.x before 2.5.2 allows remote attackers to cause a denial of service via a crafted block size.(CVE-2014-3589)

Python Image Library (PIL) 1.1.7 and earlier and Pillow 2.3 might allow remote attackers to execute arbitrary commands via shell metacharacters in unspecified vectors related to CVE-2014-1932, possibly JpegImagePlugin.py.(CVE-2014-3007)

The (1) JpegImagePlugin.py and (2) EpsImagePlugin.py scripts in Python Image Library (PIL) 1.1.7 and earlier and Pillow before 2.3.1 uses the names of temporary files on the command line, which makes it easier for local users to conduct symlink attacks by listing the processes.(CVE-2014-1933)

The (1) load_djpeg function in JpegImagePlugin.py, (2) Ghostscript function in EpsImagePlugin.py, (3) load function in IptcImagePlugin.py, and (4) _copy function in Image.py in Python Image Library (PIL) 1.1.7 and earlier and Pillow before 2.3.1 do not properly create temporary files, which allow local users to overwrite arbitrary files and obtain sensitive information via a symlink attack on the temporary file.(CVE-2014-1932)

An issue was discovered in Pillow before 6.2.0. When reading specially crafted invalid image files, the library can either allocate very large amounts of memory or take an extremely long period of time to process the image.(CVE-2019-16865)

libImaging/FliDecode.c in Pillow before 6.2.2 has an FLI buffer overflow.(CVE-2020-5313)");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Huawei EulerOS Virtualization 3.0.2.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~2.0.0~19.h5.gitd1c6db8.eulerosv2r7", rls:"EULEROSVIRT-3.0.2.2"))) {
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