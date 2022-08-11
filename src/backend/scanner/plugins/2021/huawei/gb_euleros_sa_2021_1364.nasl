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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1364");
  script_version("2021-02-22T08:41:01+0000");
  script_cve_id("CVE-2015-4171", "CVE-2015-8023", "CVE-2017-11185", "CVE-2017-9022", "CVE-2018-10811", "CVE-2018-16151", "CVE-2018-16152", "CVE-2018-17540");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-02-23 12:20:55 +0000 (Tue, 23 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-22 08:41:01 +0000 (Mon, 22 Feb 2021)");
  script_name("Huawei EulerOS: Security Advisory for strongimcv (EulerOS-SA-2021-1364)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1364");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1364");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'strongimcv' package(s) announced via the EulerOS-SA-2021-1364 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The gmp plugin in strongSwan before 5.7.1 has a Buffer Overflow via a crafted certificate.(CVE-2018-17540)

In verify_emsa_pkcs1_signature() in gmp_rsa_public_key.c in the gmp plugin in strongSwan 4.x and 5.x before 5.7.0, the RSA implementation based on GMP does not reject excess data in the digestAlgorithm.parameters field during PKCS#1 v1.5 signature verification. Consequently, a remote attacker can forge signatures when small public exponents are being used, which could lead to impersonation when only an RSA signature is used for IKEv2 authentication. This is a variant of CVE-2006-4790 and CVE-2014-1568.(CVE-2018-16152)

In verify_emsa_pkcs1_signature() in gmp_rsa_public_key.c in the gmp plugin in strongSwan 4.x and 5.x before 5.7.0, the RSA implementation based on GMP does not reject excess data after the encoded algorithm OID during PKCS#1 v1.5 signature verification. Similar to the flaw in the same version of strongSwan regarding digestAlgorithm.parameters, a remote attacker can forge signatures when small public exponents are being used, which could lead to impersonation when only an RSA signature is used for IKEv2 authentication.(CVE-2018-16151)

strongSwan 5.6.0 and older allows Remote Denial of Service because of Missing Initialization of a Variable.(CVE-2018-10811)

The gmp plugin in strongSwan before 5.5.3 does not properly validate RSA public keys before calling mpz_powm_sec, which allows remote peers to cause a denial of service (floating point exception and process crash) via a crafted certificate.(CVE-2017-9022)

The gmp plugin in strongSwan before 5.6.0 allows remote attackers to cause a denial of service (NULL pointer dereference and daemon crash) via a crafted RSA signature.(CVE-2017-11185)

The server implementation of the EAP-MSCHAPv2 protocol in the eap-mschapv2 plugin in strongSwan 4.2.12 through 5.x before 5.3.4 does not properly validate local state, which allows remote attackers to bypass authentication via an empty Success message in response to an initial Challenge message.(CVE-2015-8023)

strongSwan 4.3.0 through 5.x before 5.3.2 and strongSwan VPN Client before 1.4.6, when using EAP or pre-shared keys for authenticating an IKEv2 connection, does not enforce server authentication restrictions until the entire authentication process is complete, which allows remote servers to obtain credentials by using a valid certificate and then reading the responses.(CVE-2015-4171)");

  script_tag(name:"affected", value:"'strongimcv' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"strongimcv", rpm:"strongimcv~5.2.0~3.h2", rls:"EULEROS-2.0SP2"))) {
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