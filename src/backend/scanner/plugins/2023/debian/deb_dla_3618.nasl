# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3618");
  script_cve_id("CVE-2023-45133");
  script_tag(name:"creation_date", value:"2023-10-20 04:28:57 +0000 (Fri, 20 Oct 2023)");
  script_version("2023-10-20T05:06:03+0000");
  script_tag(name:"last_modification", value:"2023-10-20 05:06:03 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3618)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3618");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3618");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-babel");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-babel' package(s) announced via the DLA-3618 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In @babel/traverse prior to versions 7.23.2 and 8.0.0-alpha.4 and all versions of `babel-traverse`, using Babel to compile code that was specifically crafted by an attacker can lead to arbitrary code execution during compilation, when using plugins that rely on the path.evaluate() or path.evaluateTruthy() internal Babel methods.

For Debian 10 buster, this problem has been fixed in version 6.26.0+dfsg-3+deb10u1.

We recommend that you upgrade your node-babel packages.

For the detailed security status of node-babel please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'node-babel' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-cli", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-code-frame", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-core", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-generator", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-bindify-decorators", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-builder-binary-assignment-operator-visitor", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-builder-react-jsx", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-call-delegate", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-define-map", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-explode-assignable-expression", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-explode-class", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-function-name", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-get-function-arity", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-hoist-variables", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-optimise-call-expression", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-regex", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-remap-async-to-generator", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helper-replace-supers", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-helpers", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-messages", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-external-helpers", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-async-functions", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-async-generators", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-class-constructor-call", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-class-properties", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-decorators", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-do-expressions", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-dynamic-import", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-exponentiation-operator", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-export-extensions", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-flow", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-function-bind", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-jsx", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-object-rest-spread", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-syntax-trailing-function-commas", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-async-generator-functions", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-async-to-generator", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-class-constructor-call", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-class-properties", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-decorators", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-do-expressions", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-es3-member-expression-literals", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-es3-property-literals", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-exponentiation-operator", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-export-extensions", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-flow-strip-types", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-function-bind", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-jscript", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-object-rest-spread", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-proto-to-assign", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-react-display-name", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-react-jsx", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-react-jsx-self", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-react-jsx-source", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-regenerator", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-runtime", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-plugin-transform-strict-mode", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-polyfill", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-es2015", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-es2016", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-es2017", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-flow", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-latest", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-react", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-stage-0", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-stage-1", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-stage-2", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-preset-stage-3", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-register", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-runtime", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-template", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-traverse", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel-types", ver:"6.26.0+dfsg-3+deb10u1", rls:"DEB10"))) {
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
