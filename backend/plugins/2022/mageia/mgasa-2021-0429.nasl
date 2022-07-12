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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0429");
  script_cve_id("CVE-2021-3711", "CVE-2021-3712");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-31 16:37:00 +0000 (Tue, 31 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0429)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0429");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0429.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29409");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20210824.txt");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4963");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5051-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2021-0429 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In order to decrypt SM2 encrypted data an application is expected to call
the API function EVP_PKEY_decrypt(). Typically an application will call
this function twice. The first time, on entry, the 'out' parameter can be
NULL and, on exit, the 'outlen' parameter is populated with the buffer
size required to hold the decrypted plaintext. The application can then
allocate a sufficiently sized buffer and call EVP_PKEY_decrypt() again,
but this time passing a non-NULL value for the 'out' parameter. A bug in
the implementation of the SM2 decryption code means that the calculation
of the buffer size required to hold the plaintext returned by the first
call to EVP_PKEY_decrypt() can be smaller than the actual size required
by the second call. This can lead to a buffer overflow when
EVP_PKEY_decrypt() is called by the application a second time with a
buffer that is too small. A malicious attacker who is able present SM2
content for decryption to an application could cause attacker chosen
data to overflow the buffer by up to a maximum of 62 bytes altering the
contents of other data held after the buffer, possibly changing
application behaviour or causing the application to crash. The location
of the buffer is application dependent but is typically heap allocated.
(CVE-2021-3711)

ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING
structure which contains a buffer holding the string data and a field
holding the buffer length. This contrasts with normal C strings which are
represented as a buffer for the string data which is terminated with a NUL
(0) byte. Although not a strict requirement, ASN.1 strings that are
parsed using OpenSSL's own 'd2i' functions (and other similar parsing
functions) as well as any string whose value has been set with the
ASN1_STRING_set() function will additionally NUL terminate the byte array
in the ASN1_STRING structure. However, it is possible for applications to
directly construct valid ASN1_STRING structures which do not NUL
terminate the byte array by directly setting the 'data' and 'length'
fields in the ASN1_STRING array. This can also happen by using the
ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1
data have been found to assume that the ASN1_STRING byte array will be
NUL terminated, even though this is not guaranteed for strings that have
been directly constructed. Where an application requests an ASN.1
structure to be printed, and where that ASN.1 structure contains
ASN1_STRINGs that have been directly constructed by the application
without NUL terminating the 'data' field, then a read buffer overrun can
occur. The same thing can also occur during name constraints processing
of certificates (for example if a certificate has been directly
constructed by the application instead of loading it via the OpenSSL
parsing functions, and the certificate contains non NUL terminated
ASN1_STRING structures). ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.1.1l~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.1.1l~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.1", rpm:"lib64openssl1.1~1.1.1l~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.1.1l~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.1.1l~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.1", rpm:"libopenssl1.1~1.1.1l~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.1.1l~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~1.1.1l~1.mga8", rls:"MAGEIA8"))) {
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
