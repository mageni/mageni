###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsdsa_pam_ssh.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from ADV FreeBSD-SA-11:09.pam_ssh.asc
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.70763");
  script_version("$Revision: 11762 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("FreeBSD Security Advisory (FreeBSD-SA-11:09.pam_ssh.asc)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-02-12 07:37:01 -0500 (Sun, 12 Feb 2012)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdpatchlevel");

  script_tag(name:"insight", value:"The PAM (Pluggable Authentication Modules) library provides a flexible
framework for user authentication and session setup / teardown.  It is
used not only in the base system, but also by a large number of
third-party applications.

Various authentication methods (UNIX, LDAP, Kerberos etc.) are
implemented in modules which are loaded and executed according to
predefined, named policies.  These policies are defined in
/etc/pam.conf, /etc/pam.d/<policy name>, /usr/local/etc/pam.conf or
/usr/local/etc/pam.d/<policy name>.

The base system includes a module named pam_ssh which, if enabled,
allows users to authenticate themselves by typing in the passphrase of
one of the SSH private keys which are stored in encrypted form in the
their .ssh directory.  Authentication is considered successful if at
least one of these keys could be decrypted using the provided
passphrase.

By default, the pam_ssh module rejects SSH private keys with no
passphrase.  A nullok option exists to allow these keys.

The OpenSSL library call used to decrypt private keys ignores the
passphrase argument if the key is not encrypted.  Because the pam_ssh
module only checks whether the passphrase provided by the user is
null, users with unencrypted SSH private keys may successfully
authenticate themselves by providing a dummy passphrase.");

  script_tag(name:"solution", value:"Upgrade your system to the appropriate stable release
  or security branch dated after the correction date.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-11:09.pam_ssh.asc");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory FreeBSD-SA-11:09.pam_ssh.asc");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-bsd.inc");

vuln = FALSE;

if(patchlevelcmp(rel:"7.4", patchlevel:"5")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"7.3", patchlevel:"9")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"8.2", patchlevel:"5")<0) {
  vuln = TRUE;
}
if(patchlevelcmp(rel:"8.1", patchlevel:"7")<0) {
  vuln = TRUE;
}

if(vuln) {
  security_message(port:0);
} else if (__pkg_match) {
  exit(99);
}