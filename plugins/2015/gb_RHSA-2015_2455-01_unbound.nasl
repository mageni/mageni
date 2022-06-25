###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for unbound RHSA-2015:2455-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871478");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:19:50 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2014-8602");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for unbound RHSA-2015:2455-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'unbound'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The unbound packages provide a validating,
recursive, and caching DNS or DNSSEC resolver.

A denial of service flaw was found in unbound that an attacker could use to
trick the unbound resolver into following an endless loop of delegations,
consuming an excessive amount of resources. (CVE-2014-8602)

This update also fixes the following bugs:

  * Prior to this update, there was a mistake in the time configuration in
the cron job invoking unbound-anchor to update the root zone key.
Consequently, unbound-anchor was invoked once a month instead of every day,
thus not complying with RFC 5011. The cron job has been replaced with a
systemd timer unit that is invoked on a daily basis. Now, the root zone key
validity is checked daily at a random time within a 24-hour window, and
compliance with RFC 5011 is ensured. (BZ#1180267)

  * Previously, the unbound packages were installing their configuration file
for the systemd-tmpfiles utility into the /etc/tmpfiles.d/ directory. As a
consequence, changes to unbound made by the administrator in
/etc/tmpfiles.d/ could be overwritten on package reinstallation or update.
To fix this bug, unbound has been amended to install the configuration file
into the /usr/lib/tmpfiles.d/ directory. As a result, the system
administrator's configuration in /etc/tmpfiles.d/ is preserved, including
any changes, on package reinstallation or update. (BZ#1180995)

  * The unbound server default configuration included validation of DNS
records using the DNSSEC Look-aside Validation (DLV) registry. The Internet
Systems Consortium (ISC) plans to deprecate the DLV registry service as no
longer needed, and unbound could execute unnecessary steps. Therefore, the
use of the DLV registry has been removed from the unbound server default
configuration. Now, unbound does not try to perform DNS records validation
using the DLV registry. (BZ#1223339)

All unbound users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"unbound on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00049.html");
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

  if ((res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.4.20~26.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unbound-debuginfo", rpm:"unbound-debuginfo~1.4.20~26.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.4.20~26.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
