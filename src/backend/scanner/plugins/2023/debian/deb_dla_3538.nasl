# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3538");
  script_cve_id("CVE-2013-7484", "CVE-2019-17382", "CVE-2022-35229", "CVE-2022-43515", "CVE-2023-29450", "CVE-2023-29451", "CVE-2023-29454", "CVE-2023-29455", "CVE-2023-29456", "CVE-2023-29457");
  script_tag(name:"creation_date", value:"2023-08-22 14:10:57 +0000 (Tue, 22 Aug 2023)");
  script_version("2023-08-23T05:05:12+0000");
  script_tag(name:"last_modification", value:"2023-08-23 05:05:12 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-07 15:16:00 +0000 (Wed, 07 Dec 2022)");

  script_name("Debian: Security Advisory (DLA-3538)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3538");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3538");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/zabbix");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zabbix' package(s) announced via the DLA-3538 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in zabbix, a network monitoring solution, potentially allowing to crash the server, information disclosure or Cross-Site-Scripting attacks.

Important Notices: To mitigate CVE-2019-17382, on existing installations, the guest account needs to be manually disabled, for example by disabling the the Guest group in the UI: Administration -> User groups -> Guests -> Untick Enabled

This update also fixes a regression with CVE-2022-35229, which broke the possiblity to edit and add discovery rules in the UI.


CVE-2013-7484

Zabbix before version 4.4.0alpha2 stores credentials in the users table with the password hash stored as a MD5 hash, which is a known insecure hashing method. Furthermore, no salt is used with the hash.

CVE-2019-17382

(Disputed, not seen by upstream as not a security issue)

An issue was discovered in zabbix.php?actionUshboard.view&dashboardid=1 in Zabbix through 4.4. An attacker can bypass the login page and access the dashboard page, and then create a Dashboard, Report, Screen, or Map without any Username/Password (i.e., anonymously). All created elements (Dashboard/Report/Screen/Map) are accessible by other users and by an admin.

CVE-2022-35229

An authenticated user can create a link with reflected Javascript code inside it for the discovery page and send it to other users. The payload can be executed only with a known CSRF token value of the victim, which is changed periodically and is difficult to predict.

CVE-2022-43515

Zabbix Frontend provides a feature that allows admins to maintain the installation and ensure that only certain IP addresses can access it. In this way, any user will not be able to access the Zabbix Frontend while it is being maintained and possible sensitive data will be prevented from being disclosed. An attacker can bypass this protection and access the instance using IP address not listed in the defined range.

CVE-2023-29450

JavaScript pre-processing can be used by the attacker to gain access to the file system (read-only access on behalf of user zabbix) on the Zabbix Server or Zabbix Proxy, potentially leading to unauthorized access to sensitive data.

CVE-2023-29451

Specially crafted string can cause a buffer overrun in the JSON parser library leading to a crash of the Zabbix Server or a Zabbix Proxy.

CVE-2023-29454

A Stored or persistent cross-site scripting (XSS) vulnerability was found on aUsersa section in aMediaa tab in aSend toa form field. When new media is created with malicious code included into field aSend toa then it will execute when editing the same media.

CVE-2023-29455

A Reflected XSS attacks, also known as non-persistent attacks, was found where an attacker can pass malicious code as GET request to graph.php and system will save it and will execute when current graph page is opened.

CVE-2023-29456

URL validation scheme receives input from a user ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'zabbix' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:4.0.4+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:4.0.4+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:4.0.4+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:4.0.4+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:4.0.4+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:4.0.4+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:4.0.4+dfsg-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:4.0.4+dfsg-1+deb10u2", rls:"DEB10"))) {
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
