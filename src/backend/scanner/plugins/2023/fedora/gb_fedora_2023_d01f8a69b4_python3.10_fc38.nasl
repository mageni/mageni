# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885508");
  script_version("2023-12-29T16:09:56+0000");
  script_cve_id("CVE-2023-27043");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-29 16:09:56 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-27 18:50:00 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-12-28 02:18:21 +0000 (Thu, 28 Dec 2023)");
  script_name("Fedora: Security Advisory for python3.10 (FEDORA-2023-d01f8a69b4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-d01f8a69b4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/P2W2BZQIHMCKRI5FNBJERFYMS5PK6TAH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.10'
  package(s) announced via the FEDORA-2023-d01f8a69b4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python 3.10 is an accessible, high-level, dynamically typed, interpreted
programming language, designed with an emphasis on code readability.
It includes an extensive standard library, and has a vast ecosystem of
third-party libraries.

The python3.10 package provides the 'python3.10' executable: the reference
interpreter for the Python language, version 3.
The majority of its standard library is provided in the python3.10-libs package,
which should be installed automatically along with python3.10.
The remaining parts of the Python standard library are broken out into the
python3.10-tkinter and python3.10-test packages, which may need to be installed
separately.

Documentation for Python is provided in the python3.10-docs package.

Packages containing additional libraries for Python are generally named with
the 'python3.10-' prefix.");

  script_tag(name:"affected", value:"'python3.10' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.10", rpm:"python3.10~3.10.13~2.fc38", rls:"FC38"))) {
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