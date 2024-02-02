# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0003");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-01-09 04:12:12 +0000 (Tue, 09 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0003)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0003");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0003.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32672");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'putty' package(s) announced via the MGASA-2024-0003 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SSH transport protocol with certain OpenSSH extensions, found in
OpenSSH before 9.6 and many other products, allows remote attackers to
bypass integrity checks such that some packets are omitted (from the
extension negotiation message), and a client and server may consequently
end up with a connection for which some security features have been
downgraded or disabled, aka a Terrapin attack. This occurs because the
SSH Binary Packet Protocol (BPP), implemented by these extensions,
mishandles the handshake phase and mishandles use of sequence numbers.
This update fixes putty.");

  script_tag(name:"affected", value:"'putty' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"putty", rpm:"putty~0.80~1.mga9", rls:"MAGEIA9"))) {
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
