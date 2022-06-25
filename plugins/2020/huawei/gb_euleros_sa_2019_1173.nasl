# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1173");
  script_version("2020-01-23T11:33:40+0000");
  script_cve_id("CVE-2013-4122");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 11:33:40 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 11:33:40 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for cyrus-sasl (EulerOS-SA-2019-1173)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT-2\.5\.3");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1173");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'cyrus-sasl' package(s) announced via the EulerOS-SA-2019-1173 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cyrus SASL 2.1.23, 2.1.26, and earlier does not properly handle when a NULL value is returned upon an error by the crypt function as implemented in glibc 2.17 and later, which allows remote attackers to cause a denial of service (thread crash and consumption) via (1) an invalid salt or, when FIPS-140 is enabled, a (2) DES or (3) MD5 encrypted password, which triggers a NULL pointer dereference.CVE-2013-4122");

  script_tag(name:"affected", value:"'cyrus-sasl' package(s) on Huawei EulerOS Virtualization 2.5.3.");

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

if(release == "EULEROSVIRT-2.5.3") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.26~20", rls:"EULEROSVIRT-2.5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.26~20", rls:"EULEROSVIRT-2.5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-lib", rpm:"cyrus-sasl-lib~2.1.26~20", rls:"EULEROSVIRT-2.5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-md5", rpm:"cyrus-sasl-md5~2.1.26~20", rls:"EULEROSVIRT-2.5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.26~20", rls:"EULEROSVIRT-2.5.3"))) {
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