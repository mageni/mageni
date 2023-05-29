# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827667");
  script_version("2023-05-09T09:12:26+0000");
  script_cve_id("CVE-2023-26964");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-05-09 09:12:26 +0000 (Tue, 09 May 2023)");
  script_tag(name:"creation_date", value:"2023-05-08 01:06:34 +0000 (Mon, 08 May 2023)");
  script_name("Fedora: Security Advisory for keyring-ima-signer (FEDORA-2023-cc21019773)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-cc21019773");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6JEM24EZVG6TQKF5RJOBWSRWMDJJ63ZS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keyring-ima-signer'
  package(s) announced via the FEDORA-2023-cc21019773 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The IMA (Integrity Measurement Architecture) is a key component of the
Linux integrity subsystem designed to ensure integrity, authenticity,
and confidentiality of systems including hardware root of trusts (TPM).

This tool allows signing of files in userspace, inclusding options of
including the signature in xattr or a .sig file, using signing keys
stored in the kernel keyring to ensure they&#39, re not recoverable.");

  script_tag(name:"affected", value:"'keyring-ima-signer' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"keyring-ima-signer", rpm:"keyring-ima-signer~0.1.0~9.fc38", rls:"FC38"))) {
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