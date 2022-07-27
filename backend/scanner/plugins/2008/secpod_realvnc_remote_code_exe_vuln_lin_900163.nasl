##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realvnc_remote_code_exe_vuln_lin_900163.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: RealVNC VNC Viewer Remote Code Execution Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900163");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-29 14:53:11 +0100 (Wed, 29 Oct 2008)");
  script_cve_id("CVE-2008-4770");
  script_bugtraq_id(31832);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_name("RealVNC VNC Viewer Remote Code Execution Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32317/");
  script_xref(name:"URL", value:"http://www.realvnc.com/products/free/4.1/release-notes.html");

  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will allow execution of arbitrary code when user
  connects to a malicious server.");

  script_tag(name:"affected", value:"RealVNC VNC Free Edition version prior to 4.1.3 on all running platform");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Update to version 4.1.3 or later.");

  script_tag(name:"summary", value:"This host has RealVNC VNC Viewer installed and is prone to security
  vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to error in 'CMsgReader::readRect()' function in
  common/rfb/CMsgReader.cxx processing encoding types, and is exploited by sending specially crafted
  messages to the application.");

  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

command = "grep -irE 'Edition (4\\.[01](\\.[0-2])?)[^0-9\\.]' /usr/bin/vncviewer";
vncOut = ssh_cmd(socket:sock, cmd:command, timeout:120);
ssh_close_connection();

if(ereg(pattern:"Binary file.* matches", string:vncOut))
{
  security_message(port:0);
  exit(0);
}