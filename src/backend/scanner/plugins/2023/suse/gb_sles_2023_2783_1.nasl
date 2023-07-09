# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2783.1");
  script_cve_id("CVE-2018-1000518", "CVE-2020-25659", "CVE-2020-36242", "CVE-2021-22569", "CVE-2021-22570", "CVE-2022-1941", "CVE-2022-3171");
  script_tag(name:"creation_date", value:"2023-07-06 04:21:10 +0000 (Thu, 06 Jul 2023)");
  script_version("2023-07-06T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-19 17:23:00 +0000 (Fri, 19 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2783-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2783-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232783-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grpc, protobuf, pyt, python-Deprecated, python-PyGithub, python-aiocontextvars, python-avro, python-bcrypt, python-cryptography, python-cryptography-vectors, python-google-api-core' package(s) announced via the SUSE-SU-2023:2783-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for grpc, protobuf, python-Deprecated, python-PyGithub, python-aiocontextvars, python-avro, python-bcrypt, python-cryptography, python-cryptography-vectors, python-google-api-core, python-googleapis-common-protos, python-grpcio-gcp, python-humanfriendly, python-jsondiff, python-knack, python-opencensus, python-opencensus-context, python-opencensus-ext-threading, python-opentelemetry-api, python-psutil, python-pytest-asyncio, python-requests, python-websocket-client, python-websockets fixes the following issues:
grpc:
- Update in SLE-15 (bsc#1197726, bsc#1144068)
protobuf:
- Fix a potential DoS issue in protobuf-cpp and protobuf-python, CVE-2022-1941, bsc#1203681
- Fix a potential DoS issue when parsing with binary data in protobuf-java, CVE-2022-3171, bsc#1204256
- Fix potential Denial of Service in protobuf-java in the parsing procedure for binary data, CVE-2021-22569, bsc#1194530
- Add missing dependency of python subpackages on python-six (bsc#1177127)
- Updated to version 3.9.2 (bsc#1162343)
 * Remove OSReadLittle* due to alignment requirements.
 * Don't use unions and instead use memcpy for the type swaps.
- Disable LTO (bsc#1133277)
python-aiocontextvars:
- Include in SLE-15 (bsc#1199282, jsc#PM-3243, jsc#SLE-24629)
python-avro:
- Include in SLE-15 (bsc#1199282, jsc#PM-3243, jsc#SLE-24629)
- Update in SLE-15 (bsc#1199282, jsc#PM-3243, jsc#SLE-24629)
python-cryptography:
- update to 3.3.2 (bsc#1182066, CVE-2020-36242, bsc#1198331)
 * SECURITY ISSUE: Fixed a bug where certain sequences of update()
 calls when symmetrically encrypting very large payloads (>2GB) could
 result in an integer overflow, leading to buffer overflows.
 CVE-2020-36242 python-cryptography-vectors:
- update to 3.2 (bsc#1178168, CVE-2020-25659):
 * CVE-2020-25659: Attempted to make RSA PKCS#1v1.5 decryption more constant time,
 to protect against Bleichenbacher vulnerabilities. Due to limitations imposed
 by our API, we cannot completely mitigate this vulnerability.
 * Support for OpenSSL 1.0.2 has been removed.
 * Added basic support for PKCS7 signing (including SMIME) via PKCS7SignatureBuilder.
- update to 3.3.2 (bsc#1198331)
python-Deprecated:
- Include in SLE-15 (bsc#1199282, jsc#PM-3243, jsc#SLE-24629)
- update to 1.2.13:
python-google-api-core:
- Update to 1.14.2 python-googleapis-common-protos:
- Update to 1.6.0 python-grpcio-gcp:
- Initial spec for v0.2.2 python-humanfriendly:
- Update in SLE-15 (bsc#1199282, jsc#PM-3243, jsc#SLE-24629)
- Update to 10.0 python-jsondiff:
- Update in SLE-15 (bsc#1199282, jsc#PM-3243, jsc#SLE-24629)
- Update to version 1.3.0 python-knack:
- Update in SLE-15 (bsc#1199282, jsc#PM-3243, jsc#SLE-24629)
- Update to version 0.9.0 python-opencensus:
- Include in SLE-15 (bsc#1199282, jsc#PM-3243, jsc#SLE-24629)
- Disable Python2 build
- Update to 0.8.0 python-opencensus-context:
- Include in SLE-15 (bsc#1199282, jsc#PM-3243, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'grpc, protobuf, pyt, python-Deprecated, python-PyGithub, python-aiocontextvars, python-avro, python-bcrypt, python-cryptography, python-cryptography-vectors, python-google-api-core' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2, SUSE Package Hub 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite20", rpm:"libprotobuf-lite20~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite20-debuginfo", rpm:"libprotobuf-lite20-debuginfo~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf20", rpm:"libprotobuf20~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf20-debuginfo", rpm:"libprotobuf20-debuginfo~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc20", rpm:"libprotoc20~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc20-debuginfo", rpm:"libprotoc20-debuginfo~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-debugsource", rpm:"protobuf-debugsource~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel", rpm:"protobuf-devel~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel-debuginfo", rpm:"protobuf-devel-debuginfo~3.9.2~150100.8.3.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debuginfo", rpm:"python-cryptography-debuginfo~3.3.2~150100.7.15.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debugsource", rpm:"python-cryptography-debugsource~3.3.2~150100.7.15.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil-debuginfo", rpm:"python-psutil-debuginfo~5.9.1~150100.6.6.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil-debugsource", rpm:"python-psutil-debugsource~5.9.1~150100.6.6.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cryptography", rpm:"python2-cryptography~3.3.2~150100.7.15.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cryptography-debuginfo", rpm:"python2-cryptography-debuginfo~3.3.2~150100.7.15.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-psutil", rpm:"python2-psutil~5.9.1~150100.6.6.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-psutil-debuginfo", rpm:"python2-psutil-debuginfo~5.9.1~150100.6.6.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-requests", rpm:"python2-requests~2.25.1~150100.6.13.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Automat", rpm:"python3-Automat~0.6.0~150000.3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Twisted", rpm:"python3-Twisted~17.9.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Twisted-debuginfo", rpm:"python3-Twisted-debuginfo~17.9.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-constantly", rpm:"python3-constantly~15.1.0~150000.3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~3.3.2~150100.7.15.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography-debuginfo", rpm:"python3-cryptography-debuginfo~3.3.2~150100.7.15.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hyperlink", rpm:"python3-hyperlink~17.2.1~150000.3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-incremental", rpm:"python3-incremental~17.5.0~150000.3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-psutil", rpm:"python3-psutil~5.9.1~150100.6.6.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-psutil-debuginfo", rpm:"python3-psutil-debuginfo~5.9.1~150100.6.6.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.25.1~150100.6.13.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-websocket-client", rpm:"python3-websocket-client~1.3.2~150100.6.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zope.interface", rpm:"python3-zope.interface~4.4.2~150000.3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zope.interface-debuginfo", rpm:"python3-zope.interface-debuginfo~4.4.2~150000.3.4.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python-psutil-debuginfo", rpm:"python-psutil-debuginfo~5.9.1~150100.6.6.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-psutil-debugsource", rpm:"python-psutil-debugsource~5.9.1~150100.6.6.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-psutil", rpm:"python2-psutil~5.9.1~150100.6.6.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-psutil-debuginfo", rpm:"python2-psutil-debuginfo~5.9.1~150100.6.6.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-requests", rpm:"python2-requests~2.25.1~150100.6.13.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Automat", rpm:"python3-Automat~0.6.0~150000.3.4.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-constantly", rpm:"python3-constantly~15.1.0~150000.3.4.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hyperlink", rpm:"python3-hyperlink~17.2.1~150000.3.4.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-incremental", rpm:"python3-incremental~17.5.0~150000.3.4.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-psutil", rpm:"python3-psutil~5.9.1~150100.6.6.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-psutil-debuginfo", rpm:"python3-psutil-debuginfo~5.9.1~150100.6.6.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.25.1~150100.6.13.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-websocket-client", rpm:"python3-websocket-client~1.3.2~150100.6.7.3", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zope.interface", rpm:"python3-zope.interface~4.4.2~150000.3.4.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zope.interface-debuginfo", rpm:"python3-zope.interface-debuginfo~4.4.2~150000.3.4.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python-zope.interface-debuginfo", rpm:"python-zope.interface-debuginfo~4.4.2~150000.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-zope.interface-debugsource", rpm:"python-zope.interface-debugsource~4.4.2~150000.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Automat", rpm:"python3-Automat~0.6.0~150000.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-constantly", rpm:"python3-constantly~15.1.0~150000.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-hyperlink", rpm:"python3-hyperlink~17.2.1~150000.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-incremental", rpm:"python3-incremental~17.5.0~150000.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-websocket-client", rpm:"python3-websocket-client~1.3.2~150100.6.7.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zope.interface", rpm:"python3-zope.interface~4.4.2~150000.3.4.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-zope.interface-debuginfo", rpm:"python3-zope.interface-debuginfo~4.4.2~150000.3.4.1", rls:"SLES15.0SP3"))) {
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
