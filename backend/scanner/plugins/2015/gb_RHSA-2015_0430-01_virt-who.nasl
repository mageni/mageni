###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for virt-who RHSA-2015:0430-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871332");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 06:50:48 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2014-0189");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for virt-who RHSA-2015:0430-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'virt-who'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The virt-who package provides an agent that collects information about
virtual guests present in the system and reports them to the
subscription manager.

It was discovered that the /etc/sysconfig/virt-who configuration file,
which may contain hypervisor authentication credentials, was
world-readable. A local user could use this flaw to obtain authentication
credentials from this file. (CVE-2014-0189)

Red Hat would like to thank Sal Castiglione for reporting this issue.

The virt-who package has been upgraded to upstream version 0.11, which
provides a number of bug fixes and enhancements over the previous version.
The most notable bug fixes and enhancements include:

  * Support for remote libvirt.

  * A fix for using encrypted passwords.

  * Bug fixes and enhancements that increase the stability of virt-who.
(BZ#1122489)

This update also fixes the following bugs:

  * Prior to this update, the virt-who agent failed to read the list of
virtual guests provided by the VDSM daemon. As a consequence, when in VDSM
mode, the virt-who agent was not able to send updates about virtual guests
to Subscription Asset Manager (SAM) and Red Hat Satellite. With this
update, the agent reads the list of guests when in VDSM mode correctly and
reports to SAM and Satellite as expected. (BZ#1153405)

  * Previously, virt-who used incorrect information when connecting to Red
Hat Satellite 5. Consequently, virt-who could not connect to Red Hat
Satellite 5 servers. The incorrect parameter has been corrected, and
virt-who can now successfully connect to Red Hat Satellite 5. (BZ#1158859)

  * Prior to this update, virt-who did not decode the hexadecimal
representation of a password before decrypting it. As a consequence, the
decrypted password did not match the original password, and attempts to
connect using the password failed. virt-who has been updated to decode the
encrypted password and, as a result, virt-who now handles storing
credentials using encrypted passwords as expected. (BZ#1161607)

In addition, this update adds the following enhancement:

  * With this update, virt-who is able to read the list of guests from a
remote libvirt hypervisor. (BZ#1127965)

Users of virt-who are advised to upgrade to this updated package, which
corrects these issues and adds these enhancements.");
  script_tag(name:"affected", value:"virt-who on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00013.html");
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

  if ((res = isrpmvuln(pkg:"virt-who", rpm:"virt-who~0.11~5.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}