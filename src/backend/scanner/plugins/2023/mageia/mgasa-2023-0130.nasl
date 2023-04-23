# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0130");
  script_cve_id("CVE-2022-4203", "CVE-2022-4304", "CVE-2022-4450", "CVE-2023-0215", "CVE-2023-0216", "CVE-2023-0217", "CVE-2023-0286", "CVE-2023-0401", "CVE-2023-0464", "CVE-2023-0465", "CVE-2023-0466");
  script_tag(name:"creation_date", value:"2023-04-12 04:12:44 +0000 (Wed, 12 Apr 2023)");
  script_version("2023-04-12T11:20:00+0000");
  script_tag(name:"last_modification", value:"2023-04-12 11:20:00 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-29 19:37:00 +0000 (Wed, 29 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0130)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0130");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0130.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31526");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230207.txt");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5343");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5844-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/RGMDA2QI6RIJSJF3FDWES76ORE53ELXX/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/MGJS3DWIQT3W4V6WXNE2IHFLOKIFL22G/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2023:1405");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230322.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20230328.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2023-0130 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A read buffer overrun can be triggered in X.509 certificate verification,
specifically in name constraint checking. Note that this occurs after
certificate chain signature verification and requires either a CA to have
signed the malicious certificate or for the application to continue
certificate verification despite failure to construct a path to a trusted
issuer. The read buffer overrun might result in a crash which could lead
to a denial of service attack. In theory it could also result in the
disclosure of private memory contents (such as private keys, or sensitive
plaintext) although we are not aware of any working exploit leading to
memory contents disclosure as of the time of release of this advisory. In
a TLS client, this can be triggered by connecting to a malicious server.
In a TLS server, this can be triggered if the server requests client
authentication and a malicious client connects. (CVE-2022-4203)

A timing based side channel exists in the OpenSSL RSA Decryption
implementation which could be sufficient to recover a plaintext across a
network in a Bleichenbacher style attack. To achieve a successful
decryption an attacker would have to be able to send a very large number
of trial messages for decryption. The vulnerability affects all RSA
padding modes: PKCS#1 v1.5, RSA-OEAP and RSASVE. For example, in a TLS
connection, RSA is commonly used by a client to send an encrypted
pre-master secret to the server. An attacker that had observed a genuine
connection between a client and a server could use this flaw to send trial
messages to the server and record the time taken to process them. After a
sufficiently large number of messages the attacker could recover the
pre-master secret used for the original connection and thus be able to
decrypt the application data sent over that connection. (CVE-2022-4304)

The function PEM_read_bio_ex() reads a PEM file from a BIO and parses and
decodes the 'name' (e.g. 'CERTIFICATE'), any header data and the payload
data. If the function succeeds then the 'name_out', 'header' and 'data'
arguments are populated with pointers to buffers containing the relevant
decoded data. The caller is responsible for freeing those buffers. It is
possible to construct a PEM file that results in 0 bytes of payload data.
In this case PEM_read_bio_ex() will return a failure code but will
populate the header argument with a pointer to a buffer that has already
been freed. If the caller also frees this buffer then a double free will
occur. This will most likely lead to a crash. This could be exploited by
an attacker who has the ability to supply malicious PEM files for parsing
to achieve a denial of service attack. The functions PEM_read_bio() and
PEM_read() are simple wrappers around PEM_read_bio_ex() and therefore
these functions are also directly affected. These functions are also
called indirectly by a number of other OpenSSL functions ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'openssl' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.1.1t~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.1.1t~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.1", rpm:"lib64openssl1.1~1.1.1t~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.1.1t~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.1.1t~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.1", rpm:"libopenssl1.1~1.1.1t~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.1.1t~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.1.1t~1.mga8", rls:"MAGEIA8"))) {
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
