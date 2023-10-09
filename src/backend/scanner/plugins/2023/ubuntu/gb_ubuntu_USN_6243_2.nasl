# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6243.2");
  script_cve_id("CVE-2017-18638", "CVE-2022-4728", "CVE-2022-4729", "CVE-2022-4730");
  script_tag(name:"creation_date", value:"2023-08-10 04:09:25 +0000 (Thu, 10 Aug 2023)");
  script_version("2023-08-11T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-21 16:15:00 +0000 (Mon, 21 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-6243-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6243-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6243-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2030807");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphite-web' package(s) announced via the USN-6243-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6243-1 fixed vulnerabilities in Graphite-Web. It was discovered that the
applied fix was incomplete. This update fixes the problem.

Original advisory details:

 It was discovered that Graphite-Web incorrectly handled certain inputs. If a
 user or an automated system were tricked into opening a specially crafted
 input file, a remote attacker could possibly use this issue to perform
 server-side request forgery and obtain sensitive information. This issue
 only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2017-18638)

 It was discovered that Graphite-Web incorrectly handled certain inputs. If a
 user or an automated system were tricked into opening a specially crafted
 input file, a remote attacker could possibly use this issue to perform
 cross site scripting and obtain sensitive information. (CVE-2022-4728,
 CVE-2022-4729, CVE-2022-4730)");

  script_tag(name:"affected", value:"'graphite-web' package(s) on Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"graphite-web", ver:"1.0.2+debian-2ubuntu0.1~esm2", rls:"UBUNTU18.04 LTS"))) {
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
