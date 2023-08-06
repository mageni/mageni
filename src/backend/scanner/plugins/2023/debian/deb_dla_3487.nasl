# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3487");
  script_cve_id("CVE-2022-36179", "CVE-2022-36180");
  script_tag(name:"creation_date", value:"2023-07-10 04:22:05 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 13:59:00 +0000 (Mon, 28 Nov 2022)");

  script_name("Debian: Security Advisory (DLA-3487)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3487");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3487");
  script_xref(name:"URL", value:"https://fusiondirectory.example.org/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/fusiondirectory");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fusiondirectory' package(s) announced via the DLA-3487 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A potential Cross Site Scripting (XSS) vulnerablity (CVE-2022-36180) and session handling vulnerability (CVE-2022-36179 )have been found in fusiondirectory, a Web Based LDAP Administration Program.

Additionally, fusiondirectory has been updated to address the API change in php-cas due to CVE-2022-39369. see DLA 3485-1Add for details.

Due to this, if CAS authentication is used, fusiondirectory will stop working until those steps are done:

- make sure to install the updated fusiondirectory-schema package for buster.

- update the fusiondirectory core schema in LDAP by running fusiondirectory-insert-schema -m

- switch to using the new php-cas API by running fusiondirectory-setup --set-config-CasLibraryBool=TRUE

- set the CAS ClientServiceName to the base URL of the fusiondirectory installation, for example: fusiondirectory-setup --set-config-CasClientServiceName='[link moved to references]'

For Debian 10 buster, these problems have been fixed in version 1.2.3-4+deb10u2.

We recommend that you upgrade your fusiondirectory packages.

For the detailed security status of fusiondirectory please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'fusiondirectory' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-alias", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-alias-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-applications", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-applications-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-argonaut", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-argonaut-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-audit", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-audit-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-autofs", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-autofs-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-certificates", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-community", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-community-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-cyrus", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-cyrus-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-debconf", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-debconf-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-developers", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dhcp", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dhcp-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dns", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dns-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dovecot", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dovecot-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dsa", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dsa-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ejbca", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ejbca-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fai", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fai-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-freeradius", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-freeradius-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fusioninventory", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fusioninventory-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-gpg", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-gpg-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ipmi", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ipmi-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ldapdump", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ldapmanager", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-mail", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-mail-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-mixedgroups", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-nagios", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-nagios-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-netgroups", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-netgroups-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-newsletter", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-newsletter-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-opsi", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-opsi-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-personal", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-personal-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-posix", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-postfix", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-postfix-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ppolicy", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ppolicy-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-puppet", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-puppet-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-pureftpd", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-pureftpd-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-quota", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-quota-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-renater-partage", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-renater-partage-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-repository", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-repository-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-samba", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-samba-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sogo", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sogo-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-spamassassin", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-spamassassin-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-squid", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-squid-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ssh", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ssh-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-subcontracting", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-subcontracting-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sudo", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sudo-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-supann", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-supann-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sympa", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sympa-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-systems", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-systems-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-user-reminder", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-user-reminder-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-weblink", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-weblink-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-webservice", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-webservice-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-schema", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-smarty3-acl-render", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-theme-oxygen", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-webservice-shell", ver:"1.2.3-4+deb10u2", rls:"DEB10"))) {
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
