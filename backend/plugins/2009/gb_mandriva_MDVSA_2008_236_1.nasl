###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for vim MDVSA-2008:236-1 (vim)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Several vulnerabilities were found in the vim editor:

  A number of input sanitization flaws were found in various vim
  system functions.  If a user were to open a specially crafted file,
  it would be possible to execute arbitrary code as the user running vim
  (CVE-2008-2712).
  
  Ulf H&#xC3;&#xA4;rnhammar of Secunia Research found a format string flaw in
  vim's help tags processor.  If a user were tricked into executing the
  helptags command on malicious data, it could result in the execution
  of arbitrary code as the user running vim (CVE-2008-2953).
  
  A flaw was found in how tar.vim handled TAR archive browsing.  If a
  user were to open a special TAR archive using the plugin, it could
  result in the execution of arbitrary code as the user running vim
  (CVE-2008-3074).
  
  A flaw was found in how zip.vim handled ZIP archive browsing.  If a
  user were to open a special ZIP archive using the plugin, it could
  result in the execution of arbitrary code as the user running vim
  (CVE-2008-3075).
  
  A number of security flaws were found in netrw.vim, the vim plugin
  that provides the ability to read and write files over the network.
  If a user opened a specially crafted file or directory with the netrw
  plugin, it could result in the execution of arbitrary code as the
  user running vim (CVE-2008-3076).
  
  A number of input validation flaws were found in vim's keyword and
  tag handling.  If vim looked up a document's maliciously crafted
  tag or keyword, it was possible to execute arbitrary code as the user
  running vim (CVE-2008-4101).
  
  A vulnerability was found in certain versions of netrw.vim where it
  would send FTP credentials stored for an FTP session to subsequent
  FTP sessions to servers on different hosts, exposing FTP credentials
  to remote hosts (CVE-2008-4677).
  
  This update provides vim 7.2 (patchlevel 65) which corrects all of
  these issues and introduces a number of new features and bug fixes.
  
  Update:
  
  The previous vim update incorrectly introduced a requirement on
  libruby and also conflicted with a file from the git-core package
  (in contribs).  These issues have been corrected with these updated
  packages.";

tag_affected = "vim on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64,
  Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-12/msg00010.php");
  script_oid("1.3.6.1.4.1.25623.1.0.308560");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2008:236-1");
  script_cve_id("CVE-2008-2712", "CVE-2008-2953", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101", "CVE-2008-4677");
  script_name( "Mandriva Update for vim MDVSA-2008:236-1 (vim)");

  script_tag(name:"summary", value:"Check for the Version of vim");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.2.065~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.2.065~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.2.065~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.2.065~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim", rpm:"vim~7.2.065~9.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.2.065~9.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.2.065~9.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.2.065~9.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.2.065~9.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim", rpm:"vim~7.2.065~9.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.2.065~9.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.2.065~9.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.2.065~9.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.2.065~9.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim", rpm:"vim~7.2.065~9.3mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
