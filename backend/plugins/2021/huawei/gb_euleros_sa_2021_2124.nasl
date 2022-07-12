# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.2124");
  script_version("2021-07-08T06:33:31+0000");
  script_cve_id("CVE-2019-25031", "CVE-2019-25032", "CVE-2019-25033", "CVE-2019-25034", "CVE-2019-25035", "CVE-2019-25036", "CVE-2019-25037", "CVE-2019-25038", "CVE-2019-25039", "CVE-2019-25040", "CVE-2019-25041", "CVE-2019-25042");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-08 10:00:03 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-07 08:42:18 +0000 (Wed, 07 Jul 2021)");
  script_name("Huawei EulerOS: Security Advisory for unbound (EulerOS-SA-2021-2124)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-2124");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2124");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'unbound' package(s) announced via the EulerOS-SA-2021-2124 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in unbound. An out-of-bounds write in the rdata_copy function may be abused by a remote attacker. The highest threat from this vulnerability is to data confidentiality and integrity as well as service availability.(CVE-2019-25042)

A flaw was found in unbound. A reachable assertion in the dname_pkt_copy function can be triggered through compressed names. The highest threat from this vulnerability is to service availability.(CVE-2019-25041)

A flaw was found in unbound. An infinite loop in dname_pkt_copy function could be triggered by a remote attacker. The highest threat from this vulnerability is to service availability.(CVE-2019-25040)

A flaw was found in unbound. An integer overflow in ub_packed_rrset_key function may lead to a buffer overflow of the allocated buffer if the size can be controlled by an attacker. The highest threat from this vulnerability is to data confidentiality and integrity as well as service availability.(CVE-2019-25039)

A flaw was found in unbound. An integer overflow in dnsc_load_local_data function may lead to a buffer overflow of the allocated buffer if the size can be controlled by an attacker. The highest threat from this vulnerability is to data confidentiality and integrity as well as service availability.(CVE-2019-25038)

A flaw was found in unbound. A reachable assertion in the dname_pkt_copy function can be triggered by sending invalid packets to the server. The highest threat from this vulnerability is to service availability.(CVE-2019-25037)

A flaw was found in unbound. A reachable assertion in the synth_cname function can be triggered by sending invalid packets to the server. If asserts are disabled during compilation, this issue might lead to an out-of-bounds write in dname_pkt_copy function. The highest threat from this vulnerability is to data confidentiality and integrity as well as service availability.(CVE-2019-25036)

A flaw was found in unbound. An out-of-bounds write in the sldns_bget_token_par function may be abused by a remote attacker. The highest threat from this vulnerability is to data confidentiality and integrity as well as service availability.(CVE-2019-25035)

A flaw was found in unbound. An integer overflow in the sldns_str2wire_dname_buf_origin function may lead to a buffer overflow. The highest threat from this vulnerability is to data confidentiality and integrity as well as service availability.(CVE-2019-25034)

A flaw was found in unbound. An integer overflow in the regional allocator via the ALIGN_UP macro may lead to a buffer overflow if the size can be controlled by an attacker. ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'unbound' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.6.6~1.h5", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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