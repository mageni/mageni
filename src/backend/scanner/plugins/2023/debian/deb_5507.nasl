# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5507");
  script_cve_id("CVE-2023-26048", "CVE-2023-26049", "CVE-2023-36479", "CVE-2023-40167", "CVE-2023-41900");
  script_tag(name:"creation_date", value:"2023-09-29 08:17:08 +0000 (Fri, 29 Sep 2023)");
  script_version("2023-09-29T16:09:25+0000");
  script_tag(name:"last_modification", value:"2023-09-29 16:09:25 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-20 20:20:00 +0000 (Wed, 20 Sep 2023)");

  script_name("Debian: Security Advisory (DSA-5507)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5507");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5507");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5507");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/jetty9");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jetty9' package(s) announced via the DSA-5507 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities were found in Jetty, a Java based web server and servlet engine.

The org.eclipse.jetty.servlets.CGI class has been deprecated. It is potentially unsafe to use it. The upstream developers of Jetty recommend to use Fast CGI instead. See also CVE-2023-36479.

CVE-2023-26048

In affected versions servlets with multipart support (e.g. annotated with `@MultipartConfig`) that call `HttpServletRequest.getParameter()` or `HttpServletRequest.getParts()` may cause `OutOfMemoryError` when the client sends a multipart request with a part that has a name but no filename and very large content. This happens even with the default settings of `fileSizeThreshold=0` which should stream the whole part content to disk.

CVE-2023-26049

Nonstandard cookie parsing in Jetty may allow an attacker to smuggle cookies within other cookies, or otherwise perform unintended behavior by tampering with the cookie parsing mechanism.

CVE-2023-40167

Prior to this version Jetty accepted the `+` character proceeding the content-length value in a HTTP/1 header field. This is more permissive than allowed by the RFC and other servers routinely reject such requests with 400 responses. There is no known exploit scenario, but it is conceivable that request smuggling could result if jetty is used in combination with a server that does not close the connection after sending such a 400 response.

CVE-2023-36479

Users of the CgiServlet with a very specific command structure may have the wrong command executed. If a user sends a request to a org.eclipse.jetty.servlets.CGI Servlet for a binary with a space in its name, the servlet will escape the command by wrapping it in quotation marks. This wrapped command, plus an optional command prefix, will then be executed through a call to Runtime.exec. If the original binary name provided by the user contains a quotation mark followed by a space, the resulting command line will contain multiple tokens instead of one.

CVE-2023-41900

Jetty is vulnerable to weak authentication. If a Jetty `OpenIdAuthenticator` uses the optional nested `LoginService`, and that `LoginService` decides to revoke an already authenticated user, then the current request will still treat the user as authenticated. The authentication is then cleared from the session and subsequent requests will not be treated as authenticated. So a request on a previously authenticated session could be allowed to bypass authentication after it had been rejected by the `LoginService`. This impacts usages of the jetty-openid which have configured a nested `LoginService` and where that `LoginService` is capable of rejecting previously authenticated users.

For the oldstable distribution (bullseye), these problems have been fixed in version 9.4.39-3+deb11u2.

For the stable distribution (bookworm), these problems have been fixed in version 9.4.50-4+deb12u1.

We recommend that you ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'jetty9' package(s) on Debian 11, Debian 12.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"jetty9", ver:"9.4.39-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjetty9-extra-java", ver:"9.4.39-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjetty9-java", ver:"9.4.39-3+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"jetty9", ver:"9.4.50-4+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjetty9-extra-java", ver:"9.4.50-4+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjetty9-java", ver:"9.4.50-4+deb12u1", rls:"DEB12"))) {
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
