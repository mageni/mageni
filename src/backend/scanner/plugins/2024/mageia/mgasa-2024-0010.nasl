# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0010");
  script_cve_id("CVE-2023-38408", "CVE-2023-48795", "CVE-2023-51384", "CVE-2023-51385");
  script_tag(name:"creation_date", value:"2024-01-15 04:12:30 +0000 (Mon, 15 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:07:07 +0000 (Mon, 31 Jul 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0010)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0010");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0010.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32704");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6565-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/12/18/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/12/19/5");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/12/20/3");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31001");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/07/19/8");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/07/19/9");
  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-9.3p2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the MGASA-2024-0010 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an
insufficiently trustworthy search path, leading to remote code execution
if an agent is forwarded to an attacker-controlled system.
(CVE-2023-38408)
Prefix Truncation Attacks in SSH Specification (Terrapin Attack).
(CVE-2023-48795)
In ssh-agent in OpenSSH before 9.6, certain destination constraints can
be incompletely applied. When destination constraints are specified
during addition of PKCS#11-hosted private keys, these constraints are
only applied to the first key, even if a PKCS#11 token returns multiple
keys. (CVE-2023-51384)
In ssh in OpenSSH before 9.6, OS command injection might occur if a user
name or host name has shell metacharacters, and this name is referenced
by an expansion token in certain situations. For example, an untrusted
Git repository can have a submodule with shell metacharacters in a user
name or host name. (CVE-2023-51385)");

  script_tag(name:"affected", value:"'openssh' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~9.3p1~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-common", rpm:"openssh-askpass-common~9.3p1~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~9.3p1~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~9.3p1~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~9.3p1~2.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~9.3p1~2.1.mga9", rls:"MAGEIA9"))) {
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
