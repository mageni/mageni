# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6414.2");
  script_cve_id("CVE-2023-41164", "CVE-2023-43665");
  script_tag(name:"creation_date", value:"2023-10-05 04:08:26 +0000 (Thu, 05 Oct 2023)");
  script_version("2023-10-05T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-10-05 05:05:26 +0000 (Thu, 05 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6414-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6414-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6414-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-6414-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6414-1 and USN-6378-1 fixed CVE-2023-43665 and CVE-2023-41164 in Django,
respectively. This update provides the corresponding update for Ubuntu 18.04 LTS.

Original advisory details:

 Wenchao Li discovered that the Django Truncator function incorrectly
 handled very long HTML input. A remote attacker could possibly use this
 issue to cause Django to consume resources, leading to a denial of service.

 It was discovered that Django incorrectly handled certain URIs with a very
 large number of Unicode characters. A remote attacker could possibly use
 this issue to cause Django to consume resources or crash, leading to a
 denial of service.");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"1:1.11.11-1ubuntu1.21+esm2", rls:"UBUNTU18.04 LTS"))) {
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
