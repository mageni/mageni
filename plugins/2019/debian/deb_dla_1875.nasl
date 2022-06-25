# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891875");
  script_version("2019-08-13T22:56:08+0000");
  script_cve_id("CVE-2019-11187");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-08-13 22:56:08 +0000 (Tue, 13 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-12 02:00:09 +0000 (Mon, 12 Aug 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1875-1] fusiondirectory security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1875-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fusiondirectory'
  package(s) announced via the DSA-1875-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In FusionDirectory, an LDAP web-frontend written in PHP (originally
derived GOsa? 2.6.x), a vulnerability was found that could theoretically
lead to unauthorized access to the LDAP database managed with
FusionDirectory. LDAP queries' result status ('Success') checks had not
been strict enough. The resulting output containing the word 'Success'
anywhere in the returned data during login connection attempts would have
returned 'LDAP success' to FusionDirectory and possibly grant unwanted
access.");

  script_tag(name:"affected", value:"'fusiondirectory' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
1.0.8.2-5+deb8u2.

We recommend that you upgrade your fusiondirectory packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-addressbook", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-alias", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-alias-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-apache2", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-apache2-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-argonaut", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-argonaut-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-asterisk", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-asterisk-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-autofs", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-autofs-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-cyrus", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-cyrus-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dashboard", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dashboard-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-database-connector", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-debconf", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-debconf-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-desktop-management", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-desktop-management-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-developers", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dhcp", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dhcp-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dns", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dns-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dovecot", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dovecot-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dsa", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-dsa-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fai", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fai-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fax", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fax-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-freeradius", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-freeradius-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fusioninventory", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-fusioninventory-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-game", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-gpg", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-gpg-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ipmi", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ipmi-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-kolab", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-kolab-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ldapdump", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ldapmanager", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-mail", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-mail-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-nagios", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-nagios-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-netgroups", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-netgroups-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-openstack-compute", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-openstack-compute-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-opsi", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-opsi-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-puppet", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-puppet-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-pureftpd", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-pureftpd-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-quota", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-quota-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-repository", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-repository-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-rsyslog", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-samba", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-samba-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sogo", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sogo-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-squid", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-squid-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ssh", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-ssh-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sudo", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sudo-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-supann", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-supann-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sympa", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-sympa-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-systems", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-systems-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-uw-imap", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-weblink", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-weblink-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-webservice", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-plugin-webservice-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-schema", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-smarty3-acl-render", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-theme-oxygen", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"fusiondirectory-webservice-shell", ver:"1.0.8.2-5+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);