###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sssd RHSA-2015:2355-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871488");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:21:28 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-5292");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for sssd RHSA-2015:2355-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The System Security Services Daemon (SSSD)
service provides a set of daemons to manage access to remote directories and
authentication mechanisms.

It was found that SSSD's Privilege Attribute Certificate (PAC) responder
plug-in would leak a small amount of memory on each authentication request.
A remote attacker could potentially use this flaw to exhaust all available
memory on the system by making repeated requests to a Kerberized daemon
application configured to authenticate using the PAC responder plug-in.
(CVE-2015-5292)

The sssd packages have been upgraded to upstream version 1.13.0, which
provides a number of bug fixes and enhancements over the previous version.
(BZ#1205554)

Several enhancements are described in the Red Hat Enterprise Linux 7.2
Release Notes, linked to in the References section:

  * SSSD smart card support (BZ#854396)

  * Cache authentication in SSSD (BZ#910187)

  * SSSD supports overriding automatically discovered AD site (BZ#1163806)

  * SSSD can now deny SSH access to locked accounts (BZ#1175760)

  * SSSD enables UID and GID mapping on individual clients (BZ#1183747)

  * Background refresh of cached entries (BZ#1199533)

  * Multi-step prompting for one-time and long-term passwords (BZ#1200873)

  * Caching for initgroups operations (BZ#1206575)

Bugs fixed:

  * When the SELinux user content on an IdM server was set to an empty
string, the SSSD SELinux evaluation utility returned an error. (BZ#1192314)

  * If the ldap_child process failed to initialize credentials and exited
with an error multiple times, operations that create files in some cases
started failing due to an insufficient amount of i-nodes. (BZ#1198477)

  * The SRV queries used a hard coded TTL timeout, and environments that
wanted the SRV queries to be valid for a certain time only were blocked.
Now, SSSD parses the TTL value out of the DNS packet. (BZ#1199541)

  * Previously, initgroups operation took an excessive amount of time. Now,
logins and ID processing are faster for setups with AD back end and
disabled ID mapping. (BZ#1201840)

  * When an IdM client with Red Hat Enterprise Linux 7.1 or later was
connecting to a server with Red Hat Enterprise Linux 7.0 or earlier,
authentication with an AD trusted domain caused the sssd_be process to
terminate unexpectedly. (BZ#1202170)

  * If replication conflict entries appeared during HBAC processing, the user
was denied access. Now, the replication conflict entries are skipped and
users are permitted access. (BZ#1202245)

  * The array of SIDs no longer contains an uninitialized value and SSSD no
longer crashes. (BZ#1204203)

  * SSSD supports GPOs from diffe ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"sssd on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00040.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"python-sssdconfig", rpm:"python-sssdconfig~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_nss_idmap", rpm:"libsss_nss_idmap~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsss_simpleifp", rpm:"libsss_simpleifp~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libipa_hbac", rpm:"python-libipa_hbac~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libsss_nss_idmap", rpm:"python-libsss_nss_idmap~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-sss", rpm:"python-sss~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-sss-murmur", rpm:"python-sss-murmur~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-common-pac", rpm:"sssd-common-pac~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-debuginfo", rpm:"sssd-debuginfo~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-libwbclient", rpm:"sssd-libwbclient~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.13.0~40.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
