###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for freeradius RHSA-2015:1287-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871397");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2014-2015");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-23 06:24:54 +0200 (Thu, 23 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for freeradius RHSA-2015:1287-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeradius'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"FreeRADIUS is a high-performance and highly configurable free Remote
Authentication Dial In User Service (RADIUS) server, designed to allow
centralized authentication and authorization for a network.

A stack-based buffer overflow was found in the way the FreeRADIUS rlm_pap
module handled long password hashes. An attacker able to make radiusd
process a malformed password hash could cause the daemon to crash.
(CVE-2014-2015)

The freeradius packages have been upgraded to upstream version 2.2.6, which
provides a number of bug fixes and enhancements over the previous version,
including:

  * The number of dictionaries have been updated.

  * This update implements several Extensible Authentication Protocol
(EAP) improvements.

  * A number of new expansions have been added, including: %{randstr:...},
%{hex:...}, %{sha1:...}, %{base64:...}, %{tobase64:...}, and
%{base64tohex:...}.

  * Hexadecimal numbers (0x...) are now supported in %{expr:...} expansions.

  * This update adds operator support to the rlm_python module.

  * The Dynamic Host Configuration Protocol (DHCP) and DHCP relay code have
been finalized.

  * This update adds the rlm_cache module to cache arbitrary attributes.

For a complete list of bug fixes and enhancements provided by this rebase,
see the freeradius changelog linked to in the References section.

(BZ#1078736)

This update also fixes the following bugs:

  * The /var/log/radius/radutmp file was configured to rotate at one-month
intervals, even though this was unnecessary. This update removes
/var/log/radius/radutmp from the installed logrotate utility configuration
in the /etc/logrotate.d/radiusd file, and /var/log/radius/radutmp is no
longer rotated. (BZ#904578)

  * The radiusd service could not write the output file created by the
raddebug utility. The raddebug utility now sets appropriate ownership to
the output file, allowing radiusd to write the output. (BZ#921563)

  * After starting raddebug using the 'raddebug -t 0' command, raddebug
exited immediately. A typo in the special case comparison has been fixed,
and raddebug now runs for 11.5 days in this situation. (BZ#921567)

  * MS-CHAP authentication failed when the User-Name and MS-CHAP-User-Name
attributes used different encodings, even when the user provided correct
credentials. Now, MS-CHAP authentication properly handles mismatching
character encodings. Authentication with correct credentials no longer
fails in this situation. (BZ#1060319)

  * Automatically generated default certificates used the SHA-1 algorithm
message digest, which is considered insecu ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"freeradius on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-July/msg00021.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~2.2.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius-debuginfo", rpm:"freeradius-debuginfo~2.2.6~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
