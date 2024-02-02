# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3652");
  script_cve_id("CVE-2023-36823");
  script_tag(name:"creation_date", value:"2023-11-15 04:20:08 +0000 (Wed, 15 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-13 15:25:33 +0000 (Thu, 13 Jul 2023)");

  script_name("Debian: Security Advisory (DLA-3652-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3652-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3652-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-sanitize' package(s) announced via the DLA-3652-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential cross-site scripting (XSS) in ruby-sanitize, a whitelist-based HTML sanitizer.

Using carefully crafted input, an attacker may have be able to sneak arbitrary HTML and CSS through Sanitize when configured to use the built-in relaxed config or when using a custom config that allowed style elements and one or more CSS 'at'-rules. This could have resulted in cross-site scripting (XSS) or other undesired behavior if the malicious HTML and CSS were then rendered in a browser.

CVE-2023-36823

Sanitize is an allowlist-based HTML and CSS sanitizer. Using carefully crafted input, an attacker may be able to sneak arbitrary HTML and CSS through Sanitize starting with version 3.0.0 and prior to version 6.0.2 when Sanitize is configured to use the built-in 'relaxed' config or when using a custom config that allows `style` elements and one or more CSS at-rules. This could result in cross-site scripting or other undesired behavior when the malicious HTML and CSS are rendered in a browser. Sanitize 6.0.2 performs additional escaping of CSS in `style` element content, which fixes this issue.

For Debian 10 Buster, this problem has been fixed in version 4.6.6-2.1~deb10u2.

We recommend that you upgrade your ruby-sanitize packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-sanitize' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-sanitize", ver:"4.6.6-2.1~deb10u2", rls:"DEB10"))) {
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
