##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vim_shell_cmd_injection_vuln_lin_900412.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: Vim Shell Command Injection Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900412");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_bugtraq_id(32462);
  script_cve_id("CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Vim Shell Command Injection Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30731/");
  script_xref(name:"URL", value:"http://www.rdancer.org/vulnerablevim-shellescape.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary shell commands
  to compromise the system.");

  script_tag(name:"affected", value:"Vim version prior to 7.2 on Linux.");

  script_tag(name:"insight", value:"This error is due to the 'filetype.vim', 'tar.vim', 'zip.vim', 'xpm.vim',
  'xpm2.vim', 'gzip.vim', and 'netrw.vim' scripts which are insufficiently filtering special characters.");

  script_tag(name:"solution", value:"Upgrade to version 7.2 or later.");

  script_tag(name:"summary", value:"This host is installed with Vim and is prone to Command Injection
  Vulnerability.");

  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(sock)
{
  vimVer = ssh_cmd(socket:sock, cmd:"vim --version", timeout:120);
  ssh_close_connection();
  if("VIM" >< vimVer){
    pattern = "Vi IMproved ([0-6](\..*)?|7\.[01](\..*)?)";
    if(egrep(pattern:pattern, string:vimVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}
