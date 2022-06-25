###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for brltty RHSA-2010:0181-05
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "brltty (Braille TTY) is a background process (daemon) which provides access
  to the Linux console (when in text mode) for a blind person using a
  refreshable braille display. It drives the braille display, and provides
  complete screen review functionality.

  It was discovered that a brltty library had an insecure relative RPATH
  (runtime library search path) set in the ELF (Executable and Linking
  Format) header. A local user able to convince another user to run an
  application using brltty in an attacker-controlled directory, could run
  arbitrary code with the privileges of the victim. (CVE-2008-3279)
  
  These updated packages also provide fixes for the following bugs:
  
  * the brltty configuration file is documented in the brltty manual page,
  but there is no separate manual page for the /etc/brltty.conf configuration
  file: running &quot;man brltty.conf&quot; returned &quot;No manual entry for brltty.conf&quot;
  rather than opening the brltty manual entry. This update adds brltty.conf.5
  as an alias to the brltty manual page. Consequently, running &quot;man
  brltty.conf&quot; now opens the manual entry documenting the brltty.conf
  specification. (BZ#530554)
  
  * previously, the brltty-pm.conf configuration file was installed in the
  /etc/brltty/ directory. This file, which configures Papenmeier Braille
  Terminals for use with Red Hat Enterprise Linux, is optional. As well, it
  did not come with a corresponding manual page. With this update, the file
  has been moved to /usr/share/doc/brltty-3.7.2/BrailleDrivers/Papenmeier/.
  This directory also includes a README document that explains the file's
  purpose and format. (BZ#530554)
  
  * during the brltty packages installation, the message
  
  Creating screen inspection device /dev/vcsa...done.
  
  was presented at the console. This was inadequate, especially during the
  initial install of the system. These updated packages do not send any
  message to the console during installation. (BZ#529163)
  
  * although brltty contains ELF objects, the brltty-debuginfo package was
  empty. With this update, the -debuginfo package contains valid debugging
  information as expected. (BZ#500545)
  
  * the MAX_NR_CONSOLES definition was acquired by brltty by #including
  linux/tty.h in Programs/api_client.c. MAX_NR_CONSOLES has since moved to
  linux/vt.h but the #include in api_client.c was not updated. Consequently,
  brltty could not be built from the source RPM against the Red Hat
  Enterprise Linux 5 kernel. This update corrects the #include in
  api_client.c to linux/vt.h and brltty now builds from source as expected.
  (BZ#456247)
  
  All brltty users are advised to upgrade to these updated packages, which
  resolve these issues.";

tag_affected = "brltty on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00030.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314403");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:56:44 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "RHSA", value: "2010:0181-05");
  script_cve_id("CVE-2008-3279");
  script_name("RedHat Update for brltty RHSA-2010:0181-05");

  script_tag(name: "summary" , value: "Check for the Version of brltty");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"brlapi", rpm:"brlapi~0.4.1~4.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"brlapi-devel", rpm:"brlapi-devel~0.4.1~4.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"brltty", rpm:"brltty~3.7.2~4.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"brltty-debuginfo", rpm:"brltty-debuginfo~3.7.2~4.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
