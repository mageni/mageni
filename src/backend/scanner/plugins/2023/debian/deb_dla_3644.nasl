# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3644");
  script_cve_id("CVE-2023-40619");
  script_tag(name:"creation_date", value:"2023-11-03 04:19:54 +0000 (Fri, 03 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-21 18:20:39 +0000 (Thu, 21 Sep 2023)");

  script_name("Debian: Security Advisory (DLA-3644-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3644-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3644-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phppgadmin' package(s) announced via the DLA-3644-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered there was a potential remote code execution vulnerability in phppgadmin, a web-based administration tool for the PostgreSQL database server. This issue concerned the deserialisation of untrusted data, which may have led to remote code execution because user-controlled data was being passed directly to the PHP unserialize() function.

CVE-2023-40619

phpPgAdmin 7.14.4 and earlier is vulnerable to deserialization of untrusted data which may lead to remote code execution because user-controlled data is directly passed to the PHP 'unserialize()' function in multiple places. An example is the functionality to manage tables in 'tables.php' where the 'ma[]' POST parameter is deserialized.

For Debian 10 Buster, this problem has been fixed in version 5.1+ds-4+deb10u1.

We recommend that you upgrade your phppgadmin packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'phppgadmin' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"phppgadmin", ver:"5.1+ds-4+deb10u1", rls:"DEB10"))) {
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
