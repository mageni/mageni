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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5546.2");
  script_cve_id("CVE-2022-21426", "CVE-2022-21434", "CVE-2022-21443", "CVE-2022-21449", "CVE-2022-21476", "CVE-2022-21496", "CVE-2022-21540", "CVE-2022-21541", "CVE-2022-21549", "CVE-2022-34169");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-30 15:03:00 +0000 (Tue, 30 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5546-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5546-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5546-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8' package(s) announced via the USN-5546-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5546-1 fixed vulnerabilities in OpenJDK.
This update provides the corresponding updates for Ubuntu 16.04 ESM.

Original advisory details:

 Neil Madden discovered that OpenJDK did not properly verify ECDSA
 signatures. A remote attacker could possibly use this issue to insert,
 edit or obtain sensitive information. This issue only affected OpenJDK
 17 and OpenJDK 18. (CVE-2022-21449)

 It was discovered that OpenJDK incorrectly limited memory when compiling a
 specially crafted XPath expression. An attacker could possibly use this
 issue to cause a denial of service. This issue was fixed in OpenJDK 8 and
 OpenJDK 18. USN-5388-1 and USN-5388-2 addressed this issue in OpenJDK 11
 and OpenJDK 17. (CVE-2022-21426)

 It was discovered that OpenJDK incorrectly handled converting certain
 object arguments into their textual representations. An attacker could
 possibly use this issue to cause a denial of service. This issue was
 fixed in OpenJDK 8 and OpenJDK 18. USN-5388-1 and USN-5388-2 addressed
 this issue in OpenJDK 11 and OpenJDK 17. (CVE-2022-21434)

 It was discovered that OpenJDK incorrectly validated the encoded length of
 certain object identifiers. An attacker could possibly use this issue to
 cause a denial of service. This issue was fixed in OpenJDK 8 and OpenJDK 18.
 USN-5388-1 and USN-5388-2 addressed this issue in OpenJDK 11 and OpenJDK 17.
 (CVE-2022-21443)

 It was discovered that OpenJDK incorrectly validated certain paths. An
 attacker could possibly use this issue to bypass the secure validation
 feature and expose sensitive information in XML files. This issue was
 fixed in OpenJDK 8 and OpenJDK 18. USN-5388-1 and USN-5388-2 addressed this
 issue in OpenJDK 11 and OpenJDK 17. (CVE-2022-21476)

 It was discovered that OpenJDK incorrectly parsed certain URI strings. An
 attacker could possibly use this issue to make applications accept
 invalid of malformed URI strings. This issue was fixed in OpenJDK 8 and
 OpenJDK 18. USN-5388-1 and USN-5388-2 addressed this issue in OpenJDK 11
 and OpenJDK 17. (CVE-2022-21496)

 It was discovered that OpenJDK incorrectly generated class code in the
 Hotspot component. An attacker could possibly use this issue to obtain
 sensitive information. (CVE-2022-21540)

 It was discovered that OpenJDK incorrectly restricted access to the
 invokeBasic() method in the Hotspot component. An attacker could possibly
 use this issue to insert, edit or obtain sensitive information.
 (CVE-2022-21541)

 It was discovered that OpenJDK incorrectly computed exponentials. An
 attacker could possibly use this issue to insert, edit or obtain sensitive
 information. This issue only affected OpenJDK 17.
 (CVE-2022-21549)

 It was discovered that OpenJDK includes a copy of Xalan that incorrectly
 handled integer truncation. An attacker could possibly use this issue to
 execute arbitrary code. (CVE-2022-34169)");

  script_tag(name:"affected", value:"'openjdk-8' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u342-b07-0ubuntu1~16.04", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u342-b07-0ubuntu1~16.04", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u342-b07-0ubuntu1~16.04", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u342-b07-0ubuntu1~16.04", rls:"UBUNTU16.04 LTS"))) {
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
