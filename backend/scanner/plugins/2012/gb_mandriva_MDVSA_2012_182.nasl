###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for apache-mod_security MDVSA-2012:182 (apache-mod_security)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:182");
  script_oid("1.3.6.1.4.1.25623.1.0.831759");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-12-26 12:09:31 +0530 (Wed, 26 Dec 2012)");
  script_cve_id("CVE-2009-5031", "CVE-2012-2751", "CVE-2012-4528");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("Mandriva Update for apache-mod_security MDVSA-2012:182 (apache-mod_security)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-mod_security'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_2011\.0");
  script_tag(name:"affected", value:"apache-mod_security on Mandriva Linux 2011.0");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in
  apache-mod_security:

  ModSecurity before 2.6.6, when used with PHP, does not properly handle
  single quotes not at the beginning of a request parameter value in
  the Content-Disposition field of a request with a multipart/form-data
  Content-Type header, which allows remote attackers to bypass filtering
  rules and perform other attacks such as cross-site scripting (XSS)
  attacks. NOTE: this vulnerability exists because of an incomplete
  fix for CVE-2009-5031 (CVE-2012-2751).

  ModSecurity <= 2.6.8 is vulnerable to multipart/invalid part
  ruleset bypass, this was fixed in 2.7.0 (released on2012-10-16)
  (CVE-2012-4528).

  The updated packages have been patched to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"apache-mod_security", rpm:"apache-mod_security~2.6.1~1.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mlogc", rpm:"mlogc~2.6.1~1.1~mdv2011.0", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
