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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2555");
  script_cve_id("CVE-2021-45960", "CVE-2021-46143", "CVE-2022-22822", "CVE-2022-22823", "CVE-2022-22824", "CVE-2022-22825", "CVE-2022-22826", "CVE-2022-22827", "CVE-2022-23852", "CVE-2022-23990", "CVE-2022-25235", "CVE-2022-25236", "CVE-2022-25313", "CVE-2022-25314", "CVE-2022-25315");
  script_tag(name:"creation_date", value:"2022-10-12 04:41:33 +0000 (Wed, 12 Oct 2022)");
  script_version("2022-10-12T10:13:47+0000");
  script_tag(name:"last_modification", value:"2022-10-12 10:13:47 +0000 (Wed, 12 Oct 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-25 18:46:00 +0000 (Fri, 25 Feb 2022)");

  script_name("Huawei EulerOS: Security Advisory for expat (EulerOS-SA-2022-2555)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2555");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2555");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'expat' package(s) announced via the EulerOS-SA-2022-2555 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.(CVE-2022-22822)

build_model in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.(CVE-2022-22823)

defineAttribute in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.(CVE-2022-22824)

lookup in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.(CVE-2022-22825)

nextScaffoldPart in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.(CVE-2022-22826)

storeAtts in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.(CVE-2022-22827)

In doProlog in xmlparse.c in Expat (aka libexpat) before 2.4.3, an integer overflow exists for m_groupSize.(CVE-2021-46143)

In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).(CVE-2021-45960)

xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters into namespace URIs.(CVE-2022-25236)

In Expat (aka libexpat) before 2.4.5, there is an integer overflow in storeRawNames.(CVE-2022-25315)

In Expat (aka libexpat) before 2.4.5, there is an integer overflow in copyString.(CVE-2022-25314)

xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks for whether a UTF-8 character is valid in a certain context.(CVE-2022-25235)

In Expat (aka libexpat) before 2.4.5, an attacker can trigger stack exhaustion in build_model via a large nesting depth in the DTD element.(CVE-2022-25313)

Expat (aka libexpat) before 2.4.4 has an integer overflow in the doProlog function.(CVE-2022-23990)

Expat (aka libexpat) before 2.4.4 has a signed integer overflow in XML_GetBuffer, for configurations with a nonzero XML_CONTEXT_BYTES.(CVE-2022-23852)");

  script_tag(name:"affected", value:"'expat' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.2.6~1.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"expat-devel", rpm:"expat-devel~2.2.6~1.h6.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
