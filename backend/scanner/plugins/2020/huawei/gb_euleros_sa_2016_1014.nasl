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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2016.1014");
  script_version("2020-01-23T10:38:00+0000");
  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-23 10:38:00 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-23 10:38:00 +0000 (Thu, 23 Jan 2020)");
  script_name("Huawei EulerOS: Security Advisory for samba (EulerOS-SA-2016-1014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP1");

  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2016-1014");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'samba' package(s) announced via the EulerOS-SA-2016-1014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were found in Samba's DCE/RPC protocol implementation. A remote, authenticated attacker could use these flaws to cause a denial of service against the Samba server (high CPU load or a crash) or, possibly, execute arbitrary code with the permissions of the user running Samba (root). This flaw could also be used to downgrade a secure DCE/RPC connection by a man-in-the-middle attacker taking control of an Active Directory (AD) object and compromising the security of a Samba Active Directory Domain Controller (DC).(CVE-2015-5370)

A protocol flaw, publicly referred to as Badlock, was found in the Security Account Manager Remote Protocol (MS-SAMR) and the Local Security Authority (Domain Policy) Remote Protocol (MS-LSAD). Any authenticated DCE/RPC connection that a client initiates against a server could be used by a man-in-the-middle attacker to impersonate the authenticated user against the SAMR or LSA service on the server.
As a result, the attacker would be able to get read/write access to the Security Account Manager database, and use this to reveal all passwords or any other potentially sensitive information in that database. (CVE-2016-2118)

Several flaws were found in Samba's implementation of NTLMSSP authentication. An nauthenticated, man-in-the-middle attacker could use this flaw to clear the encryption and integrity flags of a connection, causing data to be transmitted in plain text. The attacker could also force the client or server into sending data in plain text even if encryption was explicitly requested for that connection.(CVE-2016-2110)

It was discovered that Samba configured as a Domain Controller would establish a secure communication channel with a machine using a spoofed computer name. A remote attacker able to observe network traffic could use this flaw to obtain session-related information about the spoofed machine. (CVE-2016-2111)

It was found that Samba's LDAP implementation did not enforce integrity protection for LDAP connections. A man-in-the-middle attacker could use this flaw to downgrade LDAP connections to use no integrity protection, allowing them to hijack such connections.(CVE-2016-2112)

It was found that Samba did not validate SSL/TLS certificates in certain connections. A man-in-the-middle attacker could use this flaw to spoof a Samba server using a specially crafted SSL/TLS certificate.(CVE-2016-2113)

It was discovered that Samba did not enforce Server Message Block (SMB) signing for clients using the SMB1 protocol. A man-in-the-middle attacker could use this flaw to modify traffic between a client and a server. (CVE-2016-2114)

It was fou ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'samba' package(s) on Huawei EulerOS V2.0SP1.");

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

if(release == "EULEROS-2.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient", rpm:"libwbclient~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common-libs", rpm:"samba-common-libs~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common-tools", rpm:"samba-common-tools~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python", rpm:"samba-python~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-modules", rpm:"samba-winbind-modules~4.2.10~6", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldb", rpm:"libldb~1.1.25~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtalloc", rpm:"libtalloc~2.1.5~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pytalloc", rpm:"pytalloc~2.1.5~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtdb", rpm:"libtdb~1.3.8~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tdb", rpm:"python-tdb~1.3.8~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tdb-tools", rpm:"tdb-tools~1.3.8~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtevent", rpm:"libtevent~0.9.26~1", rls:"EULEROS-2.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tevent", rpm:"python-tevent~0.9.26~1", rls:"EULEROS-2.0SP1"))) {
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