###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sendmail RHSA-2011:0262-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-February/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870393");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2011-02-18 15:15:05 +0100 (Fri, 18 Feb 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4565");
  script_name("RedHat Update for sendmail RHSA-2011:0262-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sendmail'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"affected", value:"sendmail on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Sendmail is a Mail Transport Agent (MTA) used to send mail between
  machines.

  A flaw was found in the way sendmail handled NUL characters in the
  CommonName field of X.509 certificates. An attacker able to get a
  carefully-crafted certificate signed by a trusted Certificate Authority
  could trick sendmail into accepting it by mistake, allowing the attacker to
  perform a man-in-the-middle attack or bypass intended client certificate
  authentication. (CVE-2009-4565)

  The CVE-2009-4565 issue only affected configurations using TLS with
  certificate verification and CommonName checking enabled, which is not a
  typical configuration.

  This update also fixes the following bugs:

  * Previously, sendmail did not correctly handle mail messages that had a
  long first header line. A line with more than 2048 characters was split,
  causing the part of the line exceeding the limit, as well as all of the
  following mail headers, to be incorrectly handled as the message body.
  (BZ#499450)

  * When an SMTP-sender is sending mail data to sendmail, it may spool that
  data to a file in the mail queue. It was found that, if the SMTP-sender
  stopped sending data and a timeout occurred, the file may have been left
  stalled in the mail queue, instead of being deleted. This update may not
  correct this issue for every situation and configuration. Refer to the
  Solution section for further information. (BZ#434645)

  * Previously, the sendmail macro MAXHOSTNAMELEN used 64 characters as the
  limit for the hostname length. However, in some cases, it was used against
  an FQDN length, which has a maximum length of 255 characters. With this
  update, the MAXHOSTNAMELEN limit has been changed to 255. (BZ#485380)

  All sendmail users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing this update,
  sendmail will be restarted automatically.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"sendmail", rpm:"sendmail~8.13.1~6.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendmail-cf", rpm:"sendmail-cf~8.13.1~6.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendmail-debuginfo", rpm:"sendmail-debuginfo~8.13.1~6.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendmail-devel", rpm:"sendmail-devel~8.13.1~6.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sendmail-doc", rpm:"sendmail-doc~8.13.1~6.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
