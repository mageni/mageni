# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2023.2977");
  script_cve_id("CVE-2023-31124", "CVE-2023-31130", "CVE-2023-31147", "CVE-2023-32067");
  script_tag(name:"creation_date", value:"2023-10-13 04:20:35 +0000 (Fri, 13 Oct 2023)");
  script_version("2023-10-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:09 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-01 13:09:00 +0000 (Thu, 01 Jun 2023)");

  script_name("Huawei EulerOS: Security Advisory for c-ares (EulerOS-SA-2023-2977)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2023-2977");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2977");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'c-ares' package(s) announced via the EulerOS-SA-2023-2977 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"c-ares is an asynchronous resolver library. When cross-compiling c-ares and using the autotools build system, CARES_RANDOM_FILE will not be set, as seen when cross compiling aarch64 android. This will downgrade to using rand() as a fallback which could allow an attacker to take advantage of the lack of entropy by not using a CSPRNG. This issue was patched in version 1.19.1.(CVE-2023-31124)

c-ares is an asynchronous resolver library. ares_inet_net_pton() is vulnerable to a buffer underflow for certain ipv6 addresses, in particular '0::00:00:00/2' was found to cause an issue. C-ares only uses this function internally for configuration purposes which would require an administrator to configure such an address via ares_set_sortlist(). However, users may externally use ares_inet_net_pton() for other purposes and thus be vulnerable to more severe issues. This issue has been fixed in 1.19.1.(CVE-2023-31130)

c-ares is an asynchronous resolver library. When /dev/urandom or RtlGenRandom() are unavailable, c-ares uses rand() to generate random numbers used for DNS query ids. This is not a CSPRNG, and it is also not seeded by srand() so will generate predictable output. Input from the random number generator is fed into a non-compilant RC4 implementation and may not be as strong as the original RC4 implementation. No attempt is made to look for modern OS-provided CSPRNGs like arc4random() that is widely available. This issue has been fixed in version 1.19.1.(CVE-2023-31147)

c-ares is an asynchronous resolver library. c-ares is vulnerable to denial of service. If a target resolver sends a query, the attacker forges a malformed UDP packet with a length of 0 and returns them to the target resolver. The target resolver erroneously interprets the 0 length as a graceful shutdown of the connection. This issue has been patched in version 1.19.1.(CVE-2023-32067)");

  script_tag(name:"affected", value:"'c-ares' package(s) on Huawei EulerOS Virtualization release 2.9.0.");

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

if(release == "EULEROSVIRT-2.9.0") {

  if(!isnull(res = isrpmvuln(pkg:"c-ares", rpm:"c-ares~1.16.0~1.h8.eulerosv2r9", rls:"EULEROSVIRT-2.9.0"))) {
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
