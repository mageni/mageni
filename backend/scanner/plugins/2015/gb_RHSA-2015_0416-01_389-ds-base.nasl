###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for 389-ds-base RHSA-2015:0416-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871323");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 06:49:04 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2014-8105", "CVE-2014-8112");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for 389-ds-base RHSA-2015:0416-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The 389 Directory Server is an LDAPv3 compliant server. The base packages
include the Lightweight Directory Access Protocol (LDAP) server and
command-line utilities for server administration.

An information disclosure flaw was found in the way the 389 Directory
Server stored information in the Changelog that is exposed via the
'cn=changelog' LDAP sub-tree. An unauthenticated user could in certain
cases use this flaw to read data from the Changelog, which could include
sensitive information such as plain-text passwords.
(CVE-2014-8105)

It was found that when the nsslapd-unhashed-pw-switch 389 Directory Server
configuration option was set to 'off', it did not prevent the writing of
unhashed passwords into the Changelog. This could potentially allow an
authenticated user able to access the Changelog to read sensitive
information. (CVE-2014-8112)

The CVE-2014-8105 issue was discovered by Petr paek of the Red Hat
Identity Management Engineering Team, and the CVE-2014-8112 issue was
discovered by Ludwig Krispenz of the Red Hat Identity Management
Engineering Team.

Enhancements:

  * Added new WinSync configuration parameters: winSyncSubtreePair for
synchronizing multiple subtrees, as well as winSyncWindowsFilter and
winSyncDirectoryFilter for synchronizing restricted sets by filters.
(BZ#746646)

  * It is now possible to stop, start, or configure plug-ins without the need
to restart the server for the change to take effect. (BZ#994690)

  * Access control related to the MODDN and MODRDN operations has been
updated: the source and destination targets can be specified in the same
access control instruction. (BZ#1118014)

  * The nsDS5ReplicaBindDNGroup attribute for using a group distinguished
name in binding to replicas has been added. (BZ#1052754)

  * WinSync now supports range retrieval. If more than the MaxValRange number
of attribute values exist per attribute, WinSync synchronizes all the
attributes to the directory server using the range retrieval. (BZ#1044149)

  * Support for the RFC 4527 Read Entry Controls and RFC 4533 Content
Synchronization Operation LDAP standards has been added. (BZ#1044139,
BZ#1044159)

  * The Referential Integrity (referint) plug-in can now use an alternate
configuration area. The PlugInArg plug-in configuration now uses unique
configuration attributes. Configuration changes no longer require a server
restart. (BZ#1044203)

  * The logconv.pl log analysis tool now supports gzip, bzip2, and xz
compressed files and also TAR archives and compressed TAR archives of these
files. (BZ#1044188)

  * Only the Directory Manager could add encoded password ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"389-ds-base on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00015.html");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.3.1~13.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-debuginfo", rpm:"389-ds-base-debuginfo~1.3.3.1~13.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.3.1~13.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
